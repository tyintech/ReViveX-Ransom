"""Generated fixtures only; no incident data or executable samples."""
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from salvage_zip import ActiveSpans, main as salvage_main
from carve_verified_formats import PNG_SIGNATURE, parse_png
from recover_inner import recover, extract, unpack


def chunk(kind, payload):
    return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload))


def indexed(raw, width, height=1, depth=8, interlace=0, colors=1):
    return (PNG_SIGNATURE + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, depth, 3, 0, 0, interlace))
            + chunk(b'PLTE', b'\0\0\0' * colors) + chunk(b'IDAT', zlib.compress(raw)) + chunk(b'IEND', b''))


class SpanTests(unittest.TestCase):
    def test_one_hundred_thousand_flat_spans_linear_operations(self):
        spans = ActiveSpans()
        for index in range(100000):
            self.assertIsNone(spans.containing(index * 10))
            spans.add(index * 10 + 1, index * 10 + 8, index * 10)
        self.assertLessEqual(spans.operations, 400000)
        self.assertLessEqual(len(spans.pending) + len(spans.active), 1)

    def test_crossing_nested_and_future_spans(self):
        spans = ActiveSpans()
        spans.add(10, 100, 0)
        spans.add(30, 60, 20)
        self.assertEqual(spans.containing(25), (10, 100, 0))
        self.assertEqual(spans.containing(35), (30, 60, 20))
        self.assertEqual(spans.containing(70), (10, 100, 0))
        self.assertIsNone(spans.containing(100))


class RecoveryRegressionTests(unittest.TestCase):
    def test_case_only_duplicates_and_unsupported_visible(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('A.txt', b'one')
            archive.writestr('a.txt', b'two')
            archive.writestr('unsupported.txt', b'three', compress_type=zipfile.ZIP_BZIP2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.bin'
            source.write_bytes(buffer.getvalue())
            with patch('sys.argv', ['salvage_zip', str(source), str(root / 'out'), '--preserve-duplicates']):
                salvage_main()
            report = json.loads((root / 'out/_salvage_manifest.json').read_text())
            self.assertEqual(report['recovered_files'], 2)
            self.assertEqual(report['unsupported_visible_candidates'], 1)
            self.assertTrue(report['records'][1]['preserved_duplicate'])
            self.assertEqual(source.read_bytes(), buffer.getvalue())
            from verify_vhdx_recovery import verify
            verification = verify(root / 'out', [root / 'out/_salvage_manifest.json', root / 'out_nested/_salvage_manifest.json'], source)
            self.assertEqual(verification['status'], 'completed', verification)
            self.assertEqual(verification['verified_outputs'], 2)

    def test_portable_ancestor_collisions_both_orders(self):
        for entries in ([('A', b'one'), ('a/child.txt', b'two')],
                        [('a/child.txt', b'one'), ('A', b'two')]):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as archive:
                for name, payload in entries:
                    archive.writestr(name, payload)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / 'input.bin'
                source.write_bytes(buffer.getvalue())
                with patch('sys.argv', ['salvage_zip', str(source), str(root / 'out'), '--preserve-duplicates']):
                    salvage_main()
                report = json.loads((root / 'out/_salvage_manifest.json').read_text())
                self.assertEqual(report['recovered_files'], 2, report['records'])
                inner_report = dict(records=[], recovered_bytes=0)
                extract(b'', buffer.getvalue(), root / 'inner', inner_report)
                self.assertEqual(sum(r['status'] == 'recovered' for r in inner_report['records']), 2)

    def test_palette_index_rejected_all_depths_filters(self):
        for depth in (1, 2, 4, 8):
            for filtering in range(5):
                value = 1 << (8 - depth)
                # First pixel predictors are zero, including Up and Paeth on row 1.
                data = indexed(bytes([filtering, value]), 1, depth=depth)
                with self.subTest(depth=depth, filtering=filtering):
                    with self.assertRaisesRegex(ValueError, 'palette index'):
                        parse_png(data, 0, len(data), 1024)

    def test_padding_bits_not_pixels_and_adam7(self):
        data = indexed(b'\x00\x7f', 1, depth=1)
        parse_png(data, 0, len(data), 1024)
        data = indexed(b'\x00\x00', 1, depth=1, interlace=1)
        parse_png(data, 0, len(data), 1024)

    def test_palette_reverse_up_and_sub(self):
        # Sub reconstructs [0,1]; Up reconstructs second row [1].
        for raw, width, height in ((b'\x01\x00\x01', 2, 1), (b'\x00\x00\x02\x01', 1, 2)):
            data = indexed(raw, width, height)
            with self.assertRaisesRegex(ValueError, 'palette index'):
                parse_png(data, 0, len(data), 1024)

    def test_truncated_specialized_recovery_writes_final_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.bin'
            source.write_bytes(b'PK\x03\x04broken')
            result = recover(source, root / 'out', 'inner.zip')
            self.assertEqual(result['status'], 'failed')
            self.assertIn('header missing', result['error'])
            self.assertTrue((root / 'out/manifest.json').exists())

    def test_inner_all_entries_accounted_and_crc_validated(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('good.txt', b'payload')
            archive.writestr('unsupported.txt', b'unsupported', compress_type=zipfile.ZIP_BZIP2)
            archive.writestr('../unsafe.txt', b'unsafe')
        with tempfile.TemporaryDirectory() as directory:
            report = dict(records=[], recovered_bytes=0)
            extract(b'', buffer.getvalue(), Path(directory), report)
            self.assertEqual(report['central_entries'], len(report['records']))
            self.assertEqual([r['status'] for r in report['records']], ['recovered', 'unsupported', 'failed'])
            self.assertEqual((Path(directory) / 'files/good.txt').read_bytes(), b'payload')

    def test_specialized_damaged_stream_end_to_end(self):
        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, 'w', zipfile.ZIP_STORED) as archive:
            archive.writestr('synthetic.bin', b'x' * 40000)
        inner = archive_bytes.getvalue()
        # Invalid first block followed by an independent non-final stored block
        # and a final empty block. No incident-specific bytes are used.
        compressed = b'\x07\x00' + struct.pack('<HH', len(inner), len(inner) ^ 65535) + inner + b'\x01\x00\x00\xff\xff'
        name = b'inner.zip'
        header = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 8, 0, 0,
                             zlib.crc32(inner), len(compressed), len(inner), len(name), 0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'damaged.bin'
            source.write_bytes(header + name + compressed)
            result = recover(source, root / 'out', 'inner.zip')
            self.assertEqual(result['status'], 'partial_salvage', result)
            self.assertEqual(result['recovered_files'], 1)
            self.assertEqual((root / 'out/files/synthetic.bin').read_bytes(), b'x' * 40000)
            from verify_vhdx_recovery import verify
            verification = verify(root / 'out', [root / 'out/manifest.json'], source)
            self.assertEqual(verification['status'], 'completed', verification)
            self.assertEqual(verification['verified_outputs'], 1)

    def test_inner_header_negative_offsets_are_rejected(self):
        with self.assertRaises(ValueError):
            unpack('<I', bytes(20), -1)


if __name__ == '__main__':
    unittest.main()
