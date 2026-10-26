from sparse_fixtures import sparse_truncate
import hashlib
import json
from pathlib import Path
import sys
import time
import zipfile

import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import revivex_jobs as jobs


def finish(runner):
    deadline = time.monotonic() + 15
    while runner.poll() is None:
        assert time.monotonic() < deadline, 'worker timed out'
        time.sleep(.02)
    return runner.poll()


def test_zip_repeated_runs_and_source_unchanged(tmp_path):
    source = tmp_path / 'input.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('folder/hello.txt', b'hello')
    before = source.read_bytes()
    runner = jobs.JobRunner()
    results = []
    for i in range(2):
        # A completed monitor may need to return after publishing its result.
        while runner.running:
            time.sleep(.001)
        runner.start(jobs.JobSpec('zip', str(source), str(tmp_path / f'job{i}')))
        result = finish(runner)
        assert result.status == 'completed', result.log
        assert len(result.rows) == 1
        row = result.rows[0]
        assert row['integrity'].startswith('verified:')
        assert row['archive_path'] == 'folder/hello.txt'
        assert Path(row['output']).read_bytes() == b'hello'
        assert json.loads((Path(result.output) / 'job_result.json').read_text())['rows'][0]['id'] == row['id']
        results.append(result)
    assert results[0].rows[0]['id'] == results[1].rows[0]['id']
    assert source.read_bytes() == before
    with pytest.raises(ValueError, match='new directory'):
        runner.start(jobs.JobSpec('zip', str(source), str(tmp_path / 'job0')))


def test_validation_and_worker_dispatch(tmp_path):
    source = tmp_path / 'input'
    source.write_bytes(b'123')
    with pytest.raises(ValueError):
        jobs.validate_spec(jobs.JobSpec('arbitrary.module', str(source), str(tmp_path / 'out')))
    with pytest.raises(ValueError):
        jobs.validate_spec(jobs.JobSpec('zip', str(source), str(tmp_path / 'out'), {'max_total_mib': 0}))
    with pytest.raises(ValueError):
        jobs.validate_spec(jobs.JobSpec('verify', str(tmp_path), str(tmp_path / 'out')))
    assert jobs.dispatch_worker(['--help']) is False
    assert jobs.worker_command('config.json', frozen=True) == [sys.executable, '--run-job', 'config.json']
    assert jobs.worker_command('config.json', frozen=False)[-2:] == ['--run-job', 'config.json']
    assert jobs.worker_command('config.json', frozen=False)[1].endswith('revivex_jobs.py')


def test_failed_tool_keeps_log_and_report(tmp_path):
    source = tmp_path / 'invalid.zip'
    source.write_bytes(b'invalid')
    runner = jobs.JobRunner()
    runner.start(jobs.JobSpec('inner', str(source), str(tmp_path / 'out'), {'outer_member': 'missing.zip'}))
    result = finish(runner)
    assert result.status == 'failed'
    assert result.summary['partial']
    assert result.summary['manifests'][0]['status'] == 'failed'


def test_cancelled_reconciliation_marks_unmanifested_partial(tmp_path):
    source = tmp_path / 'source'
    source.write_bytes(b'123')
    root = tmp_path / 'out'
    (root / 'payload').mkdir(parents=True)
    (root / 'payload' / 'partial.bin').write_bytes(b'partial')
    result = jobs.collect_results(jobs.JobSpec('zip', str(source), str(root)), -9, cancelled=True)
    assert result.status == 'cancelled'
    assert result.summary['partial']
    assert result.rows[0]['status'] == 'partial_unverified'
    assert not result.rows[0]['integrity'].startswith('verified:')


def test_cancel_running_subprocess(tmp_path):
    source = tmp_path / 'source'
    # A sparse file is sufficient to make a full probe slower than cancellation.
    with source.open('wb') as f:
        sparse_truncate(f, 512 * 1024 * 1024, temporary_root=tmp_path)
    runner = jobs.JobRunner()
    runner.start(jobs.JobSpec('probe', str(source), str(tmp_path / 'out'), {'full_scan': True}))
    runner.cancel()
    result = finish(runner)
    assert result.status == 'cancelled'
    assert result.summary['partial']
    assert source.stat().st_size == 512 * 1024 * 1024


def test_integrity_failure_and_unsafe_manifest_paths(tmp_path):
    source = tmp_path / 'source'
    source.write_bytes(b'123')
    root = tmp_path / 'out'
    payload = root / 'payload'
    payload.mkdir(parents=True)
    (payload / 'file.txt').write_bytes(b'tampered')
    report = {'schema': 'revivex.zip-salvage', 'schema_version': 1, 'files': [
        {'output': 'file.txt', 'name': 'file.txt', 'size': 2, 'sha256': hashlib.sha256(b'ok').hexdigest()},
        {'output': '../../source', 'name': 'escape', 'size': 3, 'sha256': hashlib.sha256(b'123').hexdigest()}]}
    (payload / '_salvage_manifest.json').write_text(json.dumps(report))
    result = jobs.collect_results(jobs.JobSpec('zip', str(source), str(root)), 0)
    assert len(result.rows) == 2
    assert all(row['integrity'].startswith('failed:') for row in result.rows)
    assert result.rows[1]['output'] == ''


def test_none_stdout_worker(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'123')
    root = tmp_path / 'out'
    root.mkdir()
    config = root / 'job_request.json'
    config.write_text(json.dumps({'tool': 'probe', 'source': str(source), 'output': str(root), 'options': {}}))
    monkeypatch.setattr(sys, 'stdout', None)
    monkeypatch.setattr(sys, 'stderr', None)
    monkeypatch.setattr(sys, 'argv', ['app'])
    with pytest.raises(SystemExit) as caught:
        jobs.dispatch_worker(['--run-job', str(config)])
    assert caught.value.code == 0
    assert (root / 'report.json').is_file()


def test_large_catalog_is_paged_not_returned_as_rows(tmp_path):
    from revivex_catalog import RecoveryCatalog
    source = tmp_path / 'source'
    source.write_bytes(b'123')
    root = tmp_path / 'out'
    payload = root / 'payload'
    payload.mkdir(parents=True)
    entries = []
    for i in range(1001):
        name = f'{i}.txt'
        (payload / name).write_bytes(b'ok')
        entries.append({'name': name, 'output': name, 'size': 2, 'sha256': hashlib.sha256(b'ok').hexdigest()})
    (payload / '_salvage_manifest.json').write_text(json.dumps({'schema': 'revivex.zip-salvage', 'files': entries}))
    result = jobs.collect_results(jobs.JobSpec('zip', str(source), str(root)), 0)
    assert result.rows == []
    assert result.summary['row_count'] == 1001
    with RecoveryCatalog(result.summary['catalog_path']) as catalog:
        assert catalog.count() == 1001
        assert len(catalog.query(limit=20)) == 20


def test_verify_scan_workspace_includes_nested_manifests(tmp_path):
    source = tmp_path / 'input.zip'
    with zipfile.ZipFile(source, 'w') as archive:
        archive.writestr('hello.txt', b'hello')
    runner = jobs.JobRunner()
    runner.start(jobs.JobSpec('zip', str(source), str(tmp_path / 'scan')))
    assert finish(runner).status == 'completed'
    while runner.running:
        time.sleep(.001)
    runner.start(jobs.JobSpec('verify', str(tmp_path / 'scan'), str(tmp_path / 'verify')))
    result = finish(runner)
    assert result.status == 'completed', result.log
    assert result.summary['report']['verified_outputs'] == 1
    assert len(result.summary['report']['manifests']) == 2


def test_full_worker_catalog_export_self_test():
    result = jobs.self_test(timeout=15)
    assert result['status'] == 'passed'
    assert result['engine_imports'] == len(jobs.MODULES)
    assert result['isolated_worker']
    assert result['selected_export_verified']
    assert result['source_unchanged']


def _ntfs_chain_record(number, sequence, name, parent, parent_sequence, directory=False, alternate_name=None):
    import struct
    from test_recover_vhdx_resident import resident_attribute, record_with_attributes
    encoded = name.encode('utf-16le')
    value = bytearray(66 + len(encoded))
    struct.pack_into('<Q', value, 0, parent | (parent_sequence << 48))
    value[64], value[65] = len(encoded) // 2, 1
    value[66:] = encoded
    attributes = [resident_attribute(0x30, value)]
    if alternate_name:
        alternate = alternate_name.encode('utf-16le')
        extra = bytearray(value[:66]) + alternate
        extra[64] = len(alternate) // 2
        attributes.append(resident_attribute(0x30, extra))
    if not directory:
        attributes.append(resident_attribute(0x80, b'synthetic resident content'))
    record = bytearray(record_with_attributes(attributes, flags=3 if directory else 1))
    struct.pack_into('<H', record, 16, sequence)
    struct.pack_into('<I', record, 44, number)
    return bytes(record)


def test_real_ntfs_job_catalog_inferred_paths_and_missing_parent(tmp_path):
    from revivex_catalog import RecoveryCatalog
    source = tmp_path / 'synthetic.ntfs'
    source.write_bytes(_ntfs_chain_record(5, 1, '.', 5, 1, True) +
                       _ntfs_chain_record(10, 2, 'Documents', 5, 1, True) +
                       _ntfs_chain_record(42, 3, 'example.txt', 10, 2) +
                       _ntfs_chain_record(43, 4, 'orphan.txt', 99, 1) +
                       _ntfs_chain_record(44, 5, 'linked.txt', 10, 2, alternate_name='second-link.txt'))
    runner = jobs.JobRunner()
    runner.start(jobs.JobSpec('ntfs', str(source), str(tmp_path / 'scan')))
    result = finish(runner)
    assert result.status == 'completed', result.log
    with RecoveryCatalog(result.summary['catalog_path']) as catalog:
        rows = {row['name']: row for row in catalog.query()}
        inferred = rows['example.txt']
        assert inferred['relative_path'] == 'Inferred path/Documents/example.txt'
        assert inferred['path_reliability'] == 'inferred_unverified'
        assert Path(inferred['output']).read_bytes() == b'synthetic resident content'
        assert inferred['provenance']['ntfs_path_outcomes'][0]['path_status'] == 'inferred_unverified'
        assert rows['orphan.txt']['path_reliability'] == 'name_only'
        assert rows['orphan.txt']['relative_path'].startswith('Unknown path/')
        assert rows['orphan.txt']['provenance']['path_reason'] == 'parent_not_found'

        assert rows['linked.txt']['path_reliability'] == 'name_only'
        assert len(rows['linked.txt']['provenance']['ntfs_path_outcomes']) == 2
        assert rows['linked.txt']['provenance']['path_reason'] == 'multiple_hardlink_or_path_outcomes'
