"""Independent synthetic regressions: no incident bytes or executable fixtures."""
import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

import recover_inner
import salvage_zip


def archive(entries, comment=b''):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as zip_file:
        for name, content in entries:
            zip_file.writestr(name, content)
        zip_file.comment = comment
    return out.getvalue()


class IndependentReviewTests(unittest.TestCase):
    def test_preserve_duplicates_handles_file_ancestor_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'input.zip'
            source.write_bytes(archive([('a', b'first'), ('a/child.txt', b'second')]))
            with patch('sys.argv', ['salvage_zip', str(source), str(root / 'out'), '--preserve-duplicates']), contextlib.redirect_stdout(io.StringIO()):
                salvage_zip.main()
            report = json.loads((root / 'out/_salvage_manifest.json').read_text())
            self.assertEqual(report['recovered_files'], 2, report['records'])

    def test_inner_preserves_file_ancestor_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            report = {'records': [], 'recovered_bytes': 0}
            recover_inner.extract(b'', archive([('a', b'first'), ('a/child.txt', b'second')]), Path(directory), report)
            self.assertEqual(sum(record['status'] == 'recovered' for record in report['records']), 2, report['records'])

    def test_inner_eocd_signature_inside_legal_comment(self):
        with tempfile.TemporaryDirectory() as directory:
            report = {'records': [], 'recovered_bytes': 0}
            recover_inner.extract(b'', archive([('ok.txt', b'valid')], b'ordinary-comment-PK\x05\x06'), Path(directory), report)
            self.assertEqual((Path(directory) / 'files/ok.txt').read_bytes(), b'valid')

    def test_nested_scan_skips_unrelated_unsafe_name(self):
        inner = archive([('synthetic.bin', b'x' * 40000)])
        compressed = b'\x07\x00' + struct.pack('<HH', len(inner), len(inner) ^ 65535) + inner + b'\x01\x00\x00\xff\xff'
        name = b'inner.zip'
        header = struct.pack('<4s5H3I2H', b'PK\x03\x04', 20, 0, 8, 0, 0,
                             zlib.crc32(inner), len(compressed), len(inner), len(name), 0)
        unrelated = archive([('../unsafe.txt', b'ignore')])
        prefix, suffix, _ = recover_inner.regions(unrelated + header + name + compressed, 'inner.zip')
        self.assertEqual(prefix, b'')
        self.assertEqual(suffix, inner)

    def test_stored_descriptor_crc_work_is_linear_or_bounded(self):
        count = 2000
        payload = b''.join(b'PK\x07\x08' + struct.pack('<III', 0, index * 16, index * 16) for index in range(count))
        crc_bytes = 0
        def reject_crc(data, *args):
            nonlocal crc_bytes
            crc_bytes += len(data)
            return 1
        with patch('salvage_zip.zlib.crc32', reject_crc):
            with self.assertRaises(ValueError):
                salvage_zip.stored_descriptor(payload, 0, len(payload))
        self.assertLessEqual(crc_bytes, len(payload) * 4)


if __name__ == '__main__':
    unittest.main()
