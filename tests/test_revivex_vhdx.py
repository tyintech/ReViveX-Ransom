from sparse_fixtures import sparse_truncate
import hashlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path

from revivex_vhdx import VHDXReader, VHDXError, UnsupportedVHDXError, UnreadableRangeError, crc32c
from vhdx_fixtures import build_vhdx, checksum, MB


class VHDXTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'test.vhdx'

    def mutate(self, offset, value):
        with self.path.open('r+b') as file:
            file.seek(offset)
            file.write(value)

    def rewrite_header(self, offset, field, value):
        with self.path.open('rb') as file:
            file.seek(offset)
            data = bytearray(file.read(4096))
        data[field:field + len(value)] = value
        self.mutate(offset, checksum(data))

    def test_crc_known_vector(self):
        self.assertEqual(crc32c(b'123456789'), 0xe3069283)

    def test_fixed_and_dynamic_exact_boundary_and_readonly(self):
        payload = b'A' * MB + b'B' * MB + b'C' * 512
        for fixed in (False, True):
            build_vhdx(self.path, payload, fixed=fixed)
            before = hashlib.sha256(self.path.read_bytes()).digest()
            with VHDXReader(self.path) as disk:
                self.assertEqual(disk.read_at(MB-20, 40), b'A'*20+b'B'*20)
                self.assertEqual(disk.read(), payload)
                self.assertEqual(disk.read(), b'')
                disk.seek(-512, 2)
                self.assertEqual(disk.read(1024), b'C'*512)
                self.assertFalse(disk.writable())
                with self.assertRaises(io.UnsupportedOperation):
                    disk.write(b'changed')
            self.assertEqual(before, hashlib.sha256(self.path.read_bytes()).digest())

    def test_only_explicit_zero_is_zero(self):
        for state in (0, 1, 2, 3):
            build_vhdx(self.path, bytes(MB), states=[state])
            with VHDXReader(self.path) as disk:
                if state == 2:
                    self.assertEqual(disk.read(12), bytes(12))
                else:
                    with self.assertRaises(UnreadableRangeError):
                        disk.read(12)
                    self.assertEqual(disk.tell(), 0)

    def test_damage_in_payload_does_not_hide_surviving_bytes(self):
        build_vhdx(self.path, b'X'*MB)
        with VHDXReader(self.path, damaged_ranges=[(4*MB+512, 4*MB+1024)]) as disk:
            self.assertEqual(disk.read_at(0, 512), b'X'*512)
            self.assertEqual(disk.read_at(1024, 512), b'X'*512)
            with self.assertRaises(UnreadableRangeError) as caught:
                disk.read_at(500, 20)
            self.assertEqual(caught.exception.physical_offset, 4*MB+500)

    def test_damaged_critical_metadata_is_fatal(self):
        build_vhdx(self.path, bytes(MB))
        for span in [(2*MB,2*MB+1), (3*MB+65536,3*MB+65537)]:
            with self.assertRaises(VHDXError):
                VHDXReader(self.path, damaged_ranges=[span])

    def test_invalid_newer_header_falls_back(self):
        build_vhdx(self.path, bytes(MB))
        self.mutate(131072+4, bytes(4))
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.evidence['header_sequence'], 1)

    def test_equal_sequence_is_corrupt(self):
        build_vhdx(self.path, bytes(MB))
        self.rewrite_header(131072, 8, struct.pack('<Q', 1))
        with self.assertRaises(VHDXError):
            VHDXReader(self.path)

    def test_invalid_region_copy_falls_back(self):
        build_vhdx(self.path, bytes(MB))
        self.mutate(196608+4, bytes(4))
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.evidence['region_table_offset'], 262144)

    def test_conflicting_valid_region_copies_fail(self):
        build_vhdx(self.path, bytes(MB))
        image = self.path.read_bytes()
        data = bytearray(image[196608:262144])
        struct.pack_into('<I', data, 16+28, 0)
        self.mutate(196608, checksum(data))
        with self.assertRaises(VHDXError):
            VHDXReader(self.path)

    def test_active_log_differencing_and_unsupported_states(self):
        for kwargs in ({'active_log':True}, {'parent':True}, {'states':[7]}, {'states':[4]}):
            build_vhdx(self.path, bytes(MB), **kwargs)
            with self.assertRaises(UnsupportedVHDXError):
                VHDXReader(self.path)

    def test_out_of_bounds_duplicate_and_metadata_overlap_allocations(self):
        for physical in (99*MB, 3*MB, 4*MB):
            build_vhdx(self.path, bytes(2*MB))
            self.mutate(2*MB+8, struct.pack('<Q', physical|6))
            with self.assertRaises(VHDXError):
                VHDXReader(self.path)

    def test_terabyte_logical_sparse_source_bounded_io(self):
        block_size = 256 * MB
        virtual_size = 1024**4
        build_vhdx(self.path, bytes(512), block_size=block_size, states=[2])
        self.mutate(3*MB+65544, struct.pack('<Q', virtual_size))
        count = virtual_size // block_size
        ratio = (2**23 * 512) // block_size
        with self.path.open('r+b') as file:
            sparse_truncate(file, 4*MB+block_size, temporary_root=self.temp.name)  # sparse physical allocation, not 1 TiB
            for block in range(count):
                file.seek(2*MB+8*(block+block//ratio))
                file.write(struct.pack('<Q', (4*MB)|6 if block == count-1 else 2))
            file.seek(4*MB)
            file.write(b'X'*512)
            file.seek(4*MB+block_size-512)
            file.write(b'Z'*512)
        class TrackingReader(VHDXReader):
            maximum_read = 0
            total_read = 0
            def _physical(self, offset, length):
                self.maximum_read = max(self.maximum_read, length)
                self.total_read += length
                return super()._physical(offset, length)
        with TrackingReader(self.path) as disk:
            self.assertEqual(disk.size, virtual_size)
            self.assertLessEqual(disk.maximum_read, 65536)
            self.assertLess(disk.total_read, MB)
            self.assertEqual(disk.read_at(virtual_size-block_size-512, 1024), bytes(512)+b'X'*512)
            disk.seek(-512, 2)
            self.assertEqual(disk.read(1024), b'Z'*512)
            with self.assertRaises(ValueError):
                disk.read_at(0, 65*MB)

    def test_source_change_invalidates_mapping(self):
        build_vhdx(self.path, bytes(MB))
        with VHDXReader(self.path) as disk:
            if os.name == 'nt':
                # Reader holds a deny-write handle: the mutation itself is refused.
                with self.assertRaises(PermissionError):
                    self.mutate(4*MB, b'X')
                self.assertEqual(disk.read(1), b'\x00')
            else:
                self.mutate(4*MB, b'X')
                with self.assertRaisesRegex(VHDXError, 'Source changed'):
                    disk.read(1)

    def test_partial_bat_keeps_healthy_mapping_and_blocks_invalid(self):
        payload = b'A'*MB + b'B'*MB
        for bad_entry in (99*MB|6, 6, 5, 5*MB|6|8):
            build_vhdx(self.path, payload)
            self.mutate(2*MB+8, struct.pack('<Q', bad_entry))
            with self.assertRaises(VHDXError):
                VHDXReader(self.path)
            with VHDXReader(self.path, allow_partial_bat=True) as disk:
                self.assertEqual(disk.read_at(0, 16), b'A'*16)
                self.assertTrue(disk.evidence['partial_bat'])
                self.assertFalse(disk.evidence['logical_mapping_complete'])
                self.assertEqual(disk.evidence['partial_bat_errors'][0]['bat_index'], 1)
                disk.seek(MB-8)
                with self.assertRaises(UnreadableRangeError):
                    disk.read(16)
                self.assertEqual(disk.tell(), MB-8)

    def test_partial_bat_overlap_invalidates_every_participant(self):
        build_vhdx(self.path, b'A'*MB+b'B'*MB+b'C'*MB)
        self.mutate(2*MB+8, struct.pack('<Q', 4*MB|6))
        with VHDXReader(self.path, allow_partial_bat=True) as disk:
            for offset in (0, MB):
                with self.assertRaises(UnreadableRangeError):
                    disk.read_at(offset, 8)
            self.assertEqual(disk.read_at(2*MB, 8), b'C'*8)
            self.assertEqual(len(disk.evidence['partial_bat_errors']), 2)

    def test_partial_bat_bad_bounds_still_poison_overlap(self):
        build_vhdx(self.path, b'A'*(2*MB)+b'B'*(2*MB)+b'C'*(2*MB), block_size=2*MB)
        self.mutate(2*MB+8, struct.pack('<Q', 9*MB|6))
        with VHDXReader(self.path, allow_partial_bat=True) as disk:
            self.assertEqual(disk.read_at(0, 8), b'A'*8)
            for offset in (2*MB, 4*MB):
                with self.assertRaises(UnreadableRangeError):
                    disk.read_at(offset, 8)

    def test_partial_bat_cannot_relax_critical_metadata(self):
        build_vhdx(self.path, bytes(MB))
        for span in [(2*MB, 2*MB+1), (3*MB, 3*MB+1)]:
            with self.assertRaises(VHDXError):
                VHDXReader(self.path, allow_partial_bat=True, damaged_ranges=[span])
        build_vhdx(self.path, bytes(MB), active_log=True)
        with self.assertRaises(UnsupportedVHDXError):
            VHDXReader(self.path, allow_partial_bat=True)

    def test_readinto_seek_eof_and_closed(self):
        build_vhdx(self.path, b'Z'*4096, sector_size=4096)
        disk = VHDXReader(self.path)
        target = bytearray(10)
        self.assertEqual(disk.readinto(target), 10)
        self.assertEqual(target, b'Z'*10)
        self.assertEqual(disk.tell(), 10)
        disk.seek(9000)
        self.assertEqual(disk.read(), b'')
        with self.assertRaises(ValueError):
            disk.seek(-1)
        disk.close()
        with self.assertRaises(ValueError):
            disk.read(1)


if __name__ == '__main__':
    unittest.main()
