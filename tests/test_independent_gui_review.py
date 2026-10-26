"""Independent GUI bridge/catalog safety regressions; synthetic bytes only."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import revivex_catalog
from revivex_catalog import RecoveryCatalog
from revivex_jobs import JobSpec, collect_results


def row(root, name, identity, digest=True):
    stage = root / ('stage-' + identity)
    stage.write_bytes(b'hello')
    value = dict(id=identity, name=name, relative_path=name, output=str(stage), size=5,
                 integrity='verified: size and SHA-256', path_reliability='archive member path (untrusted metadata)')
    if digest:
        value['sha256'] = hashlib.sha256(b'hello').hexdigest()
    return value


class IndependentGuiReviewTests(unittest.TestCase):
    def test_export_rejects_missing_expected_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with RecoveryCatalog(root / 'db') as cat:
                record = row(root, 'file.txt', 'one', digest=False)
                cat.ingest('s', [record])
                cat.select_filtered()
                Path(record['output']).write_bytes(b'other')
                self.assertEqual(cat.selected_count(), 0)
                with self.assertRaises(ValueError):
                    cat.export_selected(root / 'export')

    def test_generated_collision_name_is_also_reserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with RecoveryCatalog(root / 'db') as cat:
                third_id = hashlib.sha256(b's\0third').hexdigest()
                suffix = hashlib.sha256((third_id + '\0' + '1').encode()).hexdigest()[:16]
                cat.ingest('s', [row(root, 'A', 'first'), row(root, 'A__' + suffix, 'second'), row(root, 'a', 'third')])
                cat.select_filtered()
                result = cat.export_selected(root / 'export')
                self.assertEqual(result['recovered'], 3, result)
                records = [json.loads(line) for line in Path(result['report']).read_text().splitlines()]
                outputs = [record['output'].casefold() for record in records if record.get('export_status') == 'copied-and-verified']
                self.assertEqual(len(set(outputs)), 3, outputs)

    def test_selection_count_matches_atomic_export_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with RecoveryCatalog(root / 'db') as cat:
                cat.ingest('s', [row(root, str(i), str(i)) for i in range(5)])
                cat.select_filtered()
                original_usage = revivex_catalog.shutil.disk_usage
                def toggle(path):
                    cat.select_filtered(False)
                    return original_usage(path)
                with patch('revivex_catalog.shutil.disk_usage', toggle):
                    result = cat.export_selected(root / 'export')
                self.assertEqual(result['total'], result['recovered'] + result['failed'])

    def test_more_than_one_thousand_orphans_stay_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'source')
            job = root / 'job'
            payload = job / 'payload'
            payload.mkdir(parents=True)
            for index in range(1001):
                (payload / str(index)).write_bytes(b'x')
            result = collect_results(JobSpec('zip', str(source), str(job)), 0)
            self.assertEqual(result.summary['row_count'], 1001)
            self.assertTrue(result.summary['partial'])

    def test_symlink_payload_root_does_not_catalog_external_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'source')
            job = root / 'job'
            job.mkdir()
            outside = root / 'outside'
            outside.mkdir()
            (outside / 'private.txt').write_bytes(b'private')
            try:
                (job / 'payload').symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest('Symlinks unavailable')
            result = collect_results(JobSpec('zip', str(source), str(job)), 0)
            self.assertEqual(result.summary['row_count'], 0)
            self.assertEqual(result.status, 'failed')


if __name__ == '__main__':
    unittest.main()
