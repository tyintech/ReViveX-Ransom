"""Real-layout synthetic NTFS: boot BPB, fixups, fragmented MFT and DATA runs."""
from sparse_fixtures import sparse_truncate
import hashlib
import struct
import tempfile
import unittest
import zlib
from pathlib import Path
from recover_vhdx_files import recover
from verify_vhdx_recovery import verify

CLUSTER = 4096


def resident(kind, data, name='', ident=0):
    name = name.encode('utf-16le')
    value_offset = (24 + len(name) + 7) // 8 * 8
    raw = bytearray((value_offset + len(data) + 7) // 8 * 8)
    struct.pack_into('<IIBBHHH', raw, 0, kind, len(raw), 0, len(name) // 2, 24 if name else 0, 0, ident)
    struct.pack_into('<IH', raw, 16, len(data), value_offset)
    raw[24:24 + len(name)] = name
    raw[value_offset:value_offset + len(data)] = data
    return bytes(raw)


def filename(name, parent=5, sequence=1, ident=0, namespace=1):
    encoded = name.encode('utf-16le')
    raw = bytearray(66 + len(encoded))
    struct.pack_into('<Q', raw, 0, parent | sequence << 48)
    raw[64:66] = bytes((len(encoded) // 2, namespace))
    raw[66:] = encoded
    return resident(0x30, raw, ident=ident)


def nonresident(runs, size, *, initialized=None, flags=0, name='', ident=1):
    pairs = bytearray(); previous = 0
    for lcn, count in runs:
        n = max(1, (count.bit_length() + 7) // 8)
        if lcn is None:
            pairs.append(n); pairs.extend(count.to_bytes(n, 'little'))
        else:
            delta = lcn - previous; previous = lcn
            d = next(n for n in range(1, 9) if -(1 << (n * 8 - 1)) <= delta < (1 << (n * 8 - 1)))
            pairs.append(n | d << 4); pairs.extend(count.to_bytes(n, 'little')); pairs.extend(delta.to_bytes(d, 'little', signed=True))
    pairs.append(0)
    name_bytes = name.encode('utf-16le')
    header_size = 72 if flags & 0x8000 else 64
    mapping = (header_size + len(name_bytes) + 7) // 8 * 8
    raw = bytearray((mapping + len(pairs) + 7) // 8 * 8)
    struct.pack_into('<IIBBHHH', raw, 0, 0x80, len(raw), 1, len(name_bytes) // 2, header_size if name else 0, flags, ident)
    struct.pack_into('<QQH', raw, 16, 0, sum(n for _, n in runs) - 1, mapping)
    struct.pack_into('<QQQ', raw, 40, sum(n for lcn, n in runs) * CLUSTER, size, size if initialized is None else initialized)
    if flags & 0x8000:
        struct.pack_into('<Q', raw, 64, sum(n for lcn, n in runs if lcn is not None) * CLUSTER)
    raw[header_size:header_size + len(name_bytes)] = name_bytes
    raw[mapping:mapping + len(pairs)] = pairs
    return bytes(raw)


def record(number, attrs, flags=1, sequence=1):
    raw = bytearray(1024)
    raw[:4] = b'FILE'
    struct.pack_into('<HH', raw, 4, 48, 3)
    struct.pack_into('<HH', raw, 16, sequence, 1)
    body = b''.join(attrs) + b'\xff\xff\xff\xff'
    if len(body) > 968:
        raise ValueError('Test record too large')
    struct.pack_into('<HHII', raw, 20, 56, flags, 56 + len(body), 1024)
    struct.pack_into('<I', raw, 44, number)
    raw[56:56 + len(body)] = body
    raw[48:50] = b'\x12\x34'
    raw[50:52], raw[52:54] = raw[510:512], raw[1022:1024]
    raw[510:512] = raw[1022:1024] = raw[48:50]
    return bytes(raw)


def ntfs_fixture(*, file_runs=None, initialized=None, flags=0, extra_attrs=(), stale=False):
    disk = bytearray(256 * CLUSTER)
    boot = bytearray(512)
    boot[:3] = b'\xeb\x52\x90'; boot[3:11] = b'NTFS    '
    struct.pack_into('<HB', boot, 11, 512, 8)
    struct.pack_into('<QQQ', boot, 40, len(disk) // 512, 4, 30)
    struct.pack_into('<b', boot, 64, -10)
    struct.pack_into('<Q', boot, 72, 0x123456789abcdef0)
    boot[510:512] = b'\x55\xaa'
    disk[:512] = boot; disk[-512:] = boot
    runs = file_runs or [(40, 2), (50, 2)]
    payload = bytes((i * 17 + 3) % 251 for i in range(12000))
    if file_runs:
        payload = b'A' * min(12000, sum(n for _, n in runs) * CLUSTER)
    mft = bytearray(32 * 1024)
    records = {
        0: record(0, [filename('$MFT'), nonresident([(4, 4), (20, 4)], len(mft))]),
        5: record(5, [filename('.')], flags=3),
        16: record(16, [filename('Documents')], flags=3),
        17: record(17, [filename('report.bin', parent=16, sequence=2 if stale else 1),
                       filename('REPORT~1.BIN', parent=16, ident=2, namespace=2),
                       nonresident(runs, len(payload), initialized=initialized, flags=flags),
                       resident(0x80, b'named stream', name='comment', ident=3), *extra_attrs]),
        18: record(18, [filename('Empty', parent=16)], flags=3),
        19: record(19, [filename('resident.txt', parent=16), resident(0x80, b'hello')]),
    }
    for n, raw in records.items():
        mft[n * 1024:(n + 1) * 1024] = raw
    disk[4 * CLUSTER:8 * CLUSTER] = mft[:4 * CLUSTER]
    disk[20 * CLUSTER:24 * CLUSTER] = mft[4 * CLUSTER:]
    disk[30 * CLUSTER:30 * CLUSTER + 1024] = records[0]
    pos = 0
    for lcn, count in runs:
        part = payload[pos:pos + count * CLUSTER]
        if lcn is not None:
            disk[lcn * CLUSTER:lcn * CLUSTER + len(part)] = part
        pos += count * CLUSTER
    return bytes(disk), payload


def mbr_disk(volume):
    raw = bytearray(2048 * 512 + len(volume))
    raw[510:512] = b'\x55\xaa'
    raw[450] = 7
    struct.pack_into('<II', raw, 454, 2048, len(volume) // 512)
    raw[2048 * 512:] = volume
    return bytes(raw)


def gpt_disk(volume):
    import uuid
    start = 2048
    sectors = start + len(volume) // 512 + 34
    raw = bytearray(sectors * 512)
    raw[510:512] = b'\x55\xaa'; raw[450] = 0xee
    struct.pack_into('<II', raw, 454, 1, sectors - 1)
    entries = bytearray(128 * 128)
    entries[:16] = uuid.UUID('ebd0a0a2-b9e5-4433-87c0-68b6b72699c7').bytes_le
    entries[16:32] = uuid.UUID(int=2).bytes_le
    struct.pack_into('<QQ', entries, 32, start, start + len(volume) // 512 - 1)
    header = bytearray(512); header[:8] = b'EFI PART'
    struct.pack_into('<III', header, 8, 0x10000, 92, 0)
    struct.pack_into('<QQQQ', header, 24, 1, sectors - 1, 34, sectors - 34)
    header[56:72] = uuid.UUID(int=1).bytes_le
    struct.pack_into('<QIII', header, 72, 2, 128, 128, zlib.crc32(entries))
    struct.pack_into('<I', header, 16, zlib.crc32(header[:92]))
    raw[512:1024] = header; raw[1024:1024 + len(entries)] = entries
    raw[start * 512:start * 512 + len(volume)] = volume
    return bytes(raw)


class LogicalRecoveryTests(unittest.TestCase):
    def run_fixture(self, data, **options):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); source = root / 'disk.img'; source.write_bytes(data)
        output = root / 'output'
        result = recover(source, output, **options)
        self.assertEqual(source.read_bytes(), data)
        return result, output

    def primary(self, report):
        return next(row for row in report['files'] if row.get('record_number') == 17 and row.get('stream_name') == '')

    def test_fragmented_mft_and_nonresident_file_and_named_stream(self):
        data, expected = ntfs_fixture()
        report, output = self.run_fixture(data)
        row = self.primary(report)
        self.assertEqual(row['status'], 'recovered', report)
        self.assertEqual((output / row['output']).read_bytes(), expected)
        self.assertEqual(row['sha256'], hashlib.sha256(expected).hexdigest())
        self.assertIn('/Documents/report.bin', row['paths'])
        self.assertIn('/Documents/REPORT~1.BIN', row['paths'])
        self.assertEqual(row['path_status'], 'verified_mft_parent_sequence_chain')
        self.assertEqual(len(row['file_names']), 2)
        self.assertEqual(report['counts']['recovered_streams'], 3)
        self.assertEqual(verify(output)['verified_outputs'], 3)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['completeness'], 'unknown')

    def test_mbr_and_gpt(self):
        data, expected = ntfs_fixture()
        for wrap in (mbr_disk, gpt_disk):
            with self.subTest(wrap=wrap.__name__):
                report, output = self.run_fixture(wrap(data))
                self.assertEqual((output / self.primary(report)['output']).read_bytes(), expected)

    def test_gpt_crc_corruption_is_not_guessed(self):
        data = bytearray(gpt_disk(ntfs_fixture()[0])); data[512 + 16] ^= 1
        report, _ = self.run_fixture(data)
        self.assertEqual(report['scan_status'], 'failed')
        self.assertIn('CRC', report['errors'][0])

    def test_sparse_and_uninitialized_are_only_metadata_defined_zeros(self):
        data, _ = ntfs_fixture(file_runs=[(40, 1), (None, 1), (50, 1)], flags=0x8000, initialized=9000)
        report, output = self.run_fixture(data)
        row = self.primary(report); payload = (output / row['output']).read_bytes()
        self.assertEqual(payload[:4096], b'A' * 4096)
        self.assertEqual(payload[4096:8192], bytes(4096))
        self.assertEqual(payload[8192:9000], b'A' * 808)
        self.assertEqual(payload[9000:], bytes(3000))

    def test_damage_partial_never_recovered(self):
        data, _ = ntfs_fixture()
        report, output = self.run_fixture(data, damaged_ranges=[(50 * CLUSTER, 51 * CLUSTER)], chunk_size=4096)
        row = self.primary(report)
        self.assertEqual(row['status'], 'partial')
        self.assertEqual(row['size'], 8192)
        self.assertEqual((output / row['output']).stat().st_size, 8192)
        self.assertEqual(report['counts']['recovered_streams'], 2)

    def test_stale_parent_is_not_verified(self):
        report, _ = self.run_fixture(ntfs_fixture(stale=True)[0])
        self.assertEqual(self.primary(report)['path_status'], 'unknown')

    def test_compressed_and_efs_explicit_unsupported(self):
        for flags in (1, 0x4000):
            report, _ = self.run_fixture(ntfs_fixture(flags=flags)[0])
            self.assertEqual(self.primary(report)['status'], 'unsupported')

    def test_attribute_list_explicit_unsupported(self):
        report, _ = self.run_fixture(ntfs_fixture(extra_attrs=[resident(0x20, bytes(32))])[0])
        row = next(row for row in report['files'] if row.get('record_number') == 17)
        self.assertEqual(row['status'], 'unsupported')
        self.assertIn('attribute_list', row['reason'])

    def test_validated_backup_boot_and_mirror(self):
        data = bytearray(mbr_disk(ntfs_fixture()[0])); offset = 2048 * 512
        data[offset + 3] ^= 1
        report, _ = self.run_fixture(data)
        self.assertEqual(report['volumes'][0]['boot_source'], 'validated_backup_at_partition_end')
        data = bytearray(ntfs_fixture()[0]); data[4 * CLUSTER] = 0
        report, _ = self.run_fixture(data)
        self.assertEqual(report['volumes'][0]['mft_source'], 'validated_mirror_bootstrap')
        self.assertEqual(self.primary(report)['status'], 'recovered')

    def test_sector4096_explicit_unsupported(self):
        data = bytearray(ntfs_fixture()[0]); struct.pack_into('<H', data, 11, 4096)
        report, _ = self.run_fixture(data)
        self.assertEqual(report['volumes'][0]['scan_status'], 'unsupported')

    def test_cancel_and_limits_and_fresh_dir(self):
        report, _ = self.run_fixture(ntfs_fixture()[0], cancel=lambda: True)
        self.assertEqual(report['scan_status'], 'cancelled')
        report, output = self.run_fixture(ntfs_fixture()[0], max_file_bytes=10)
        self.assertEqual(self.primary(report)['status'], 'unsupported')
        with self.assertRaises(ValueError):
            recover(output.parent / 'disk.img', output)

    def test_metadata_only_does_not_touch_damaged_payload(self):
        data, _ = ntfs_fixture()
        report, output = self.run_fixture(data, metadata_only=True, damaged_ranges=[(40 * CLUSTER, 54 * CLUSTER)])
        self.assertEqual(self.primary(report)['status'], 'indexed')
        self.assertEqual(report['counts']['exported_bytes'], 0)
        self.assertTrue((output / 'ntfs_records_0.sqlite').is_file())
        self.assertIn('Documents/Empty', [row['relative_path'] for row in report['directories']])

    def test_terabyte_sparse_source_metadata_reads_are_bounded(self):
        from unittest.mock import patch
        import recover_vhdx_files as engine
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); source = root / 'large.raw'
        data = bytearray(ntfs_fixture()[0]); size = 1024**4
        struct.pack_into('<Q', data, 40, size // 512)
        with source.open('wb') as fh:
            fh.write(data); sparse_truncate(fh, size, temporary_root=root)
        read_bytes = 0
        original = engine.RawReader.read_at
        def counted(reader, offset, length):
            nonlocal read_bytes
            read_bytes += length
            return original(reader, offset, length)
        with patch.object(engine.RawReader, 'read_at', counted):
            report = recover(source, root / 'out', metadata_only=True)
        self.assertEqual(self.primary(report)['status'], 'indexed')
        self.assertLess(read_bytes, 128 * 1024)
        self.assertEqual(report['source_size'], size)

    def test_nested_empty_directories_and_same_basename(self):
        data = bytearray(ntfs_fixture()[0])
        # Slot 18 is Empty beneath Documents; put slot 20 beneath Empty with the same basename.
        raw = record(20, [filename('report.bin', parent=18), resident(0x80, b'nested')])
        data[21 * CLUSTER:21 * CLUSTER + 1024] = raw
        report, output = self.run_fixture(data)
        row = next(r for r in report['files'] if r.get('record_number') == 20)
        self.assertEqual(row['relative_path'], 'Documents/Empty/report.bin')
        self.assertNotEqual(row['output'], self.primary(report)['output'])
        self.assertEqual((output / row['output']).read_bytes(), b'nested')


    def test_partial_bat_is_explicit_and_preserves_only_healthy_file(self):
        from vhdx_fixtures import build_vhdx, MB
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        data, expected = ntfs_fixture()
        data = bytearray(data + bytes(MB))
        struct.pack_into('<Q', data, 40, len(data) // 512)
        data[-512:] = data[:512]
        bad_file = record(20, [filename('unreadable.bin', parent=16), nonresident([(300, 3)], 12000)])
        data[21 * CLUSTER:21 * CLUSTER + 1024] = bad_file
        path = build_vhdx(root / 'broken.vhdx', data)
        with path.open('r+b') as fh:
            fh.seek(2 * MB + 8); fh.write(struct.pack('<Q', 99 * MB | 6))
        strict = recover(path, root / 'strict')
        self.assertEqual(strict['scan_status'], 'failed')
        self.assertEqual(strict['counts']['recovered_streams'], 0)
        report = recover(path, root / 'partial', allow_partial_bat=True)
        row = self.primary(report)
        self.assertEqual(row['status'], 'recovered')
        self.assertEqual((root / 'partial' / row['output']).read_bytes(), expected)
        bad = next(row for row in report['files'] if row.get('record_number') == 20)
        self.assertEqual(bad['status'], 'partial')
        self.assertEqual(bad['size'], 0)
        self.assertTrue(report['source_mapping']['partial_bat'])
        self.assertFalse(report['source_mapping']['logical_mapping_complete'])
        self.assertEqual(len(report['source_mapping']['partial_bat_errors']), 1)
        self.assertEqual(report['status'], 'partial')
        raw = root / 'raw'; raw.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'only to VHDX'):
            recover(raw, root / 'rawout', allow_partial_bat=True)


    def test_real_vhdx_mapping(self):
        from vhdx_fixtures import build_vhdx
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); data, expected = ntfs_fixture()
        path = build_vhdx(root / 'disk.vhdx', data)
        report = recover(path, root / 'out')
        row = self.primary(report)
        self.assertEqual(row['status'], 'recovered', report)
        self.assertEqual((root / 'out' / row['output']).read_bytes(), expected)


if __name__ == '__main__':
    unittest.main()
