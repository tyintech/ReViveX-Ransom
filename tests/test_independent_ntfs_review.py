"""Independent generated resident-record review fixtures."""
import tempfile
import unittest
from pathlib import Path

from recover_vhdx_resident import recover
from test_recover_vhdx_resident import filename_attribute, make_record, record_with_attributes, resident_attribute
from verify_vhdx_recovery import verify


class IndependentNtfsReviewTests(unittest.TestCase):
    def test_long_unicode_filename_does_not_abort_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.bin'
            source.write_bytes(record_with_attributes([
                filename_attribute('测' * 100), resident_attribute(0x80, b'first')]) + make_record())
            report = recover(source, root / 'out')
            self.assertEqual(report['status'], 'completed')
            self.assertEqual(report['counts']['resident_streams'], 2)
            self.assertEqual(report['files'][0]['name'], '测' * 100)
            verification = verify(root / 'out', source=source)
            self.assertEqual(verification['status'], 'completed')
            self.assertEqual(verification['verified_outputs'], 2)
            self.assertEqual(verification['source_verification'], 'no_reference_hash')

    def test_resident_manifest_generic_verification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.bin'
            source.write_bytes(make_record())
            recover(source, root / 'out')
            report = verify(root / 'out', source=source)
            self.assertEqual(report['status'], 'completed')
            self.assertEqual(report['verified_outputs'], 1)
            self.assertEqual(report['source_verification'], 'no_reference_hash')


if __name__ == '__main__':
    unittest.main()
