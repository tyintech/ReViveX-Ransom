"""Synthetic recovery acceptance regressions and explicitly unsupported boundaries."""
import contextlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from salvage_zip import main as salvage_main
from recover_inner import recover
from revivex_jobs import JobSpec, collect_results
from carve_verified_formats import sqlite_extent, verify_sqlite


def local(name, payload, flags=0, method=0, descriptor=False):
    raw = name.encode()
    crc = zlib.crc32(payload)
    header = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, flags, method, 0, 0,
                         0 if descriptor else crc, 0 if descriptor else len(payload),
                         0 if descriptor else len(payload), len(raw), 0)
    return header + raw + payload + (struct.pack('<III', crc, len(payload), len(payload)) if descriptor else b'')


def salvage(root, payload, *args):
    source = root / 'source.bin'
    source.write_bytes(payload)
    with patch('sys.argv', ['salvage_zip', str(source), str(root / 'payload'), *args]), contextlib.redirect_stdout(io.StringIO()):
        salvage_main()
    return json.loads((root / 'payload/_salvage_manifest.json').read_text()), source


class AdditionalAudit(unittest.TestCase):
    def test_unsigned_stored_descriptor_intact_member_is_lost(self):
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = salvage(Path(tmp), local('good.txt', b'intact data', flags=8, descriptor=True))
            self.assertEqual(report['recovered_files'], 1)
            self.assertEqual((Path(tmp) / 'payload/good.txt').read_bytes(), b'intact data')

    def test_size_limit_completed_scan_is_known_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report, source = salvage(root, local('too-large.txt', b'x' * (1048576 + 1)), '--max-file-mib', '1')
            self.assertEqual(report['failed_visible_candidates'], 1)
            self.assertEqual(report['status'], 'completed_partial_salvage')
            result = collect_results(JobSpec('zip', str(source), str(root)), 0)
            self.assertEqual(result.status, 'completed')
            self.assertTrue(result.summary['partial'])  # Completed scan does not imply complete recovery.

    def test_intact_bzip2_and_lzma_members_are_unsupported(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('bzip.txt', b'intact', compress_type=zipfile.ZIP_BZIP2)
            archive.writestr('lzma.txt', b'intact', compress_type=zipfile.ZIP_LZMA)
        with zipfile.ZipFile(io.BytesIO(stream.getvalue())) as archive:
            self.assertEqual([archive.read(n) for n in archive.namelist()], [b'intact', b'intact'])
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = salvage(Path(tmp), stream.getvalue())
            self.assertEqual(report['recovered_files'], 0)
            self.assertEqual(report['unsupported_visible_candidates'], 2)

    def test_inner_intact_prefix_member_discarded_with_failed_chunk(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_STORED) as archive:
            archive.writestr('prefix.txt', b'intact prefix')
            archive.writestr('suffix.txt', b's' * 40000)
        inner = stream.getvalue()
        split = 30 + len('prefix.txt') + len(b'intact prefix')
        # First complete member decodes before the invalid block, but in the
        # same 4096-byte decoder call. The later member is independently valid.
        a, b = inner[:split], inner[split:]
        compressed = (b'\x00' + struct.pack('<HH', len(a), len(a) ^ 65535) + a + b'\x07' +
                      b'\x00' + struct.pack('<HH', len(b), len(b) ^ 65535) + b + b'\x01\x00\x00\xff\xff')
        name = b'inner.zip'
        outer = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 8, 0, 0, zlib.crc32(inner), len(compressed), len(inner), len(name), 0) + name + compressed
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.bin'
            source.write_bytes(outer)
            report = recover(source, root / 'output', 'inner.zip')
            self.assertEqual(report['prefix_size'], split)
            self.assertEqual(report['recovered_files'], 2)
            self.assertEqual([r['status'] for r in report['records']], ['recovered', 'recovered'])

    def test_valid_central_crc_cannot_rescue_damaged_local_crc(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('intact.txt', b'intact payload')
        data = bytearray(stream.getvalue())
        data[14] ^= 1
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(archive.read('intact.txt'), b'intact payload')
        with tempfile.TemporaryDirectory() as tmp:
            report, _ = salvage(Path(tmp), data)
            self.assertEqual(report['recovered_files'], 1)
            self.assertIn('central_directory', report['records'][0]['metadata_evidence'])

    def test_inner_final_stored_block_restart_not_recognized(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('intact.txt', b'x' * 40000)
        inner = stream.getvalue()
        final_block = b'\x01' + struct.pack('<HH', len(inner), len(inner) ^ 65535) + inner
        self.assertEqual(zlib.decompress(final_block, -15), inner)
        compressed = b'\x07' + final_block
        name = b'inner.zip'
        outer = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 8, 0, 0, zlib.crc32(inner), len(compressed), len(inner), len(name), 0) + name + compressed
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'source.bin'
            source.write_bytes(outer)
            report = recover(source, root / 'output', 'inner.zip')
            self.assertEqual(report['status'], 'partial_salvage')
            self.assertEqual(report['recovered_files'], 1)
            self.assertTrue(report['restart_final_block'])

    def test_valid_sqlite_without_inheader_page_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'db.sqlite'
            with contextlib.closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE example (value TEXT)')
                db.execute("INSERT INTO example VALUES ('intact')")
                db.commit()
            data = bytearray(path.read_bytes())
            data[28:32] = bytes(4)
            path.write_bytes(data)
            self.assertEqual(verify_sqlite(path)['integrity_check'], 'ok')
            with self.assertRaisesRegex(ValueError, 'page count is absent or stale'):
                sqlite_extent(data, 0, len(data))
            end, evidence = sqlite_extent(data, 0, len(data), standalone=True)
            self.assertEqual(end, len(data))
            self.assertEqual(evidence['extent_source'], 'explicit_standalone_file_boundary')
