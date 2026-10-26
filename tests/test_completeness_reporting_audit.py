"""Completeness regression tests: omissions remain visible and scans never imply full recovery.

Run: PYTHONPATH=src:tests python -m unittest discover -s tests -p test_completeness_reporting_audit.py -v
No original input or recovered executable is executed.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import sqlite3
import sys
import tempfile
import time
import unittest
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from revivex_jobs import JobSpec, JobRunner, collect_results
from revivex_catalog import RecoveryCatalog
from carve_verified_formats import carve, PNG_SIGNATURE


def png(rgb):
    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))
    return PNG_SIGNATURE + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0)) + chunk(b'IDAT', zlib.compress(b'\0' + rgb)) + chunk(b'IEND', b'')


class CompletenessReportingAudit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def job(self, tool, source, options=None):
        runner = JobRunner()
        runner.start(JobSpec(tool, str(source), str(self.root / 'job'), options or {}))
        deadline = time.monotonic() + 15
        while runner.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.01)
        runner._thread.join(2)
        return runner.poll()

    def test_zip_crc_failure_is_visible_and_known_partial(self):
        source = self.root / 'mixed.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('intact.txt', b'good fixture')
            archive.writestr('damaged.txt', b'bad fixture')
        source.write_bytes(source.read_bytes().replace(b'bad fixture', b'BAD fixture'))
        result = self.job('zip', source)
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.summary['partial'])
        self.assertEqual(result.summary['manifests'][0]['failed_visible_candidates'], 1)
        with RecoveryCatalog(result.summary['catalog_path']) as catalog:
            self.assertEqual(catalog.count(), 2)
            self.assertEqual(catalog.count(status='failed'), 1)
            self.assertEqual(result.summary['completeness'], 'known_partial')
            self.assertEqual(result.summary['verified_available'], 1)
            catalog.select_filtered()
            exported = catalog.export_selected(self.root / 'export')
        self.assertEqual((exported['total'], exported['recovered'], exported['failed']), (1, 1, 0))
        # Selected-copy report does not retain the source scan's failed candidate.
        lines = [json.loads(line) for line in Path(exported['report']).read_text().splitlines()]
        self.assertEqual(lines[0]['scan_summary']['known_failed'], 1)
        self.assertIsNone(lines[0]['scan_summary']['original_total'])
        self.assertEqual(lines[1]['export_status'], 'copied-and-verified')
        self.assertIn('destination matches staged bytes', lines[1]['final_integrity'])
        self.assertTrue((Path(result.output) / 'job_result.json').is_file())

    def test_zip_destroyed_header_is_not_counted_as_unrecovered(self):
        source = self.root / 'missing-header.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('intact.txt', b'intact')
            archive.writestr('invisible.txt', b'original invisible content')
        data = source.read_bytes()
        offset = data.index(b'PK\x03\x04', 4)
        source.write_bytes(data[:offset] + b'XXXX' + data[offset + 4:])
        result = self.job('zip', source)
        summary = result.summary['manifests'][0]
        self.assertEqual(summary['recovered_files'], 2)
        self.assertEqual(summary['failed_visible_candidates'], 0)
        self.assertEqual(summary['unsupported_visible_candidates'], 0)
        self.assertFalse(result.summary['partial'])
        self.assertEqual(result.summary['completeness'], 'unknown')
        self.assertIsNone(result.summary['original_total'])

    def test_zip_candidate_limit_is_failed_not_success(self):
        source = self.root / 'limited.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            archive.writestr('one.txt', b'one')
            archive.writestr('two.txt', b'two')
        result = self.job('zip', source, {'max_candidates': 1})
        self.assertEqual(result.status, 'failed')
        self.assertTrue(result.summary['partial'])
        self.assertFalse(result.summary['manifests'][0]['scan_complete'])

    def test_carve_output_budget_rejection_is_visible_and_partial(self):
        source = self.root / 'images.bin'
        first, second = png(b'\xff\0\0'), png(b'\0\xff\0')
        source.write_bytes(first + second)
        run = self.root / 'job'
        run.mkdir()
        with contextlib.redirect_stdout(io.StringIO()):
            report = carve(source, run / 'payload', max_file=4096, max_total=len(first), max_decoded=4096)
        result = collect_results(JobSpec('carve', str(source), str(run)), 0)
        self.assertEqual(report['counts']['png_candidates'], 2)
        self.assertEqual(report['counts']['png_rejected'], 1)
        self.assertIn('png: Total output byte limit exceeded', report['rejection_reasons'])
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.summary['partial'])
        self.assertEqual(result.summary['row_count'], 2)
        with RecoveryCatalog(result.summary['catalog_path']) as catalog:
            self.assertEqual(catalog.count(status='rejected'), 1)

    def test_carve_worker_sqlite_size_limit_completed_scan_known_partial(self):
        database = self.root / 'large.sqlite'
        connection = sqlite3.connect(database)
        with connection:
            connection.execute('CREATE TABLE data (payload BLOB)')
            connection.execute('INSERT INTO data VALUES (zeroblob(1100000))')
        connection.close()  # Windows cannot delete an open database file
        source = self.root / 'combined.bin'
        source.write_bytes(png(b'\xff\0\0') + database.read_bytes())
        result = self.job('carve', source, {'max_file_mib': 1})
        counts = result.summary['manifests'][0]['counts']
        self.assertEqual(counts['png_unique_outputs'], 1)
        self.assertEqual(counts['sqlite_candidates'], 1)
        self.assertEqual(counts['sqlite_rejected'], 1)
        self.assertEqual(result.summary['returncode'], 0)
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.summary['partial'])
        self.assertEqual(result.summary['row_count'], 2)

    def test_cancelled_unmanifested_file_is_blocked_from_export(self):
        source = self.root / 'source.bin'
        source.write_bytes(b'fixture')
        run = self.root / 'job'
        (run / 'payload').mkdir(parents=True)
        (run / 'payload' / 'partial.bin').write_bytes(b'incomplete')
        result = collect_results(JobSpec('zip', str(source), str(run)), -9, cancelled=True)
        self.assertEqual(result.status, 'cancelled')
        self.assertTrue(result.summary['partial'])
        self.assertEqual(result.rows[0]['status'], 'partial_unverified')
        with RecoveryCatalog(result.summary['catalog_path']) as catalog:
            catalog.select_filtered()
            self.assertEqual(catalog.selected_count(), 0)
            with self.assertRaises(ValueError):
                catalog.export_selected(self.root / 'export')

    def test_ntfs_nonresident_and_invalid_records_cataloged(self):
        try:
            import dissect.ntfs
        except ImportError:
            self.skipTest('dissect.ntfs not installed')
        from test_recover_vhdx_resident import make_record, record_with_attributes
        attr = bytearray(64)
        struct.pack_into('<II', attr, 0, 0x80, 64)
        attr[8] = 1
        bad = bytearray(make_record())
        bad[510] ^= 1
        source = self.root / 'ntfs.bin'
        source.write_bytes(make_record() + record_with_attributes([attr]) + bad)
        result = self.job('ntfs', source)
        counts = result.summary['manifests'][0]['counts']
        self.assertEqual((counts['resident_streams'], counts['nonresident_streams'], counts['invalid_records']), (1, 1, 1))
        self.assertEqual(result.summary['row_count'], 3)
        self.assertEqual(result.status, 'completed')
        self.assertTrue(result.summary['partial'])

    def test_ntfs_scan_limit_real_worker_marks_partial(self):
        try:
            import dissect.ntfs
        except ImportError:
            self.skipTest('dissect.ntfs not installed')
        from test_recover_vhdx_resident import make_record
        source = self.root / 'ntfs.bin'
        source.write_bytes(make_record() * 2)
        result = self.job('ntfs', source, {'max_scan_bytes': 1024})
        self.assertEqual(result.summary['manifests'][0]['status'], 'scan_limit')
        self.assertEqual(result.summary['returncode'], 2)
        self.assertEqual(result.status, 'failed')
        self.assertTrue(result.summary['partial'])

    def test_gui_row_selection_preserves_run_diagnostics(self):
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
        try:
            from PySide6.QtWidgets import QApplication
            from revivex_ui import MainWindow
        except ImportError:
            self.skipTest('PySide6 not installed')
        app = QApplication.instance() or QApplication([])
        window = MainWindow(persist_settings=False)
        window.set_language('en')
        catalog = RecoveryCatalog(self.root / 'catalog.sqlite')
        catalog.ingest('fixture', [dict(name='one.txt', size=1, status='recovered', integrity='verified: size and SHA-256')])
        window.catalog_ready(catalog)
        window.details.setPlainText('{"failed_visible_candidates": 3}')
        window.table.selectRow(0)
        app.processEvents()
        self.assertIn('failed_visible_candidates', window.details.toPlainText())
        self.assertIn('one.txt', window.row_details.toPlainText())
        self.assertEqual(window.display_status('partial_unverified'), 'Partial output · unverified')
        window.close()
        catalog.close()


if __name__ == '__main__':
    unittest.main()
