"""The 'auto' job type: validation, worker arguments, streamed result import,
continue-in-place, and the desktop UI starting it and showing stage progress."""
import hashlib
import json
import os
import time
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest

from field_fixtures import build_field_case
from revivex_auto import AutoRecovery
from revivex_catalog import RecoveryCatalog
from revivex_jobs import JobRunner, JobSpec, build_arguments, collect_results, reopen_workspace, validate_spec


@pytest.fixture(scope='module')
def field(tmp_path_factory):
    root = tmp_path_factory.mktemp('jobs-auto')
    source, truth = build_field_case(root)
    return root, source, truth


def wait(runner, timeout=120):
    deadline = time.monotonic() + timeout
    while runner.poll() is None:
        assert time.monotonic() < deadline, 'auto job timed out'
        time.sleep(0.05)
    return runner.poll()


def test_auto_job_validation_and_arguments(field, tmp_path):
    root, source, _ = field
    fast = tmp_path / 'fast'
    fast.mkdir()
    spec = validate_spec(JobSpec('auto', str(source), str(tmp_path / 'job'),
                                 dict(max_file_mib=8, max_total_mib=64, work_dir=str(fast), damaged_range=['0-4096'])))
    args = build_arguments(spec)
    assert args[:4] == [spec.source, str(Path(spec.output) / 'payload'), '--progress', str(Path(spec.output) / 'progress.json')]
    assert args[args.index('--work-dir') + 1] == str(fast)
    assert args[args.index('--damaged-range') + 1] == '0-4096'
    with pytest.raises(ValueError):
        validate_spec(JobSpec('auto', str(source), str(tmp_path / 'j2'), dict(work_dir=str(tmp_path / 'missing'))))
    with pytest.raises(ValueError):
        validate_spec(JobSpec('auto', str(source), str(tmp_path / 'j3'), dict(unknown=1)))
    with pytest.raises(ValueError):  # continuing needs a previous automatic-recovery folder
        validate_spec(JobSpec('auto', str(source), str(tmp_path), dict(resume=True)))


def test_auto_job_runs_in_isolated_worker(field, tmp_path):
    root, source, truth = field
    fast = tmp_path / 'fast'
    fast.mkdir()
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    runner = JobRunner()
    runner.start(JobSpec('auto', str(source), str(tmp_path / 'job'), dict(work_dir=str(fast), reserve_mib=1)))
    stages = set()
    deadline = time.monotonic() + 120
    while runner.poll() is None:
        assert time.monotonic() < deadline
        try:
            stages.add(json.loads((tmp_path / 'job' / 'progress.json').read_text(encoding='utf-8'))['stage'])
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.01)
    result = runner.poll()
    assert result.status == 'completed', (result.error, result.log[-3000:])
    final = json.loads((tmp_path / 'job' / 'progress.json').read_text(encoding='utf-8'))
    assert final['stage'] == 'done' and final['stage_count'] == 11 and final['status'] == 'completed'
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    summary = result.summary
    assert summary['tool'] == 'auto' and summary['known_failed'] == 2  # victim.bin + deleted gone.jpg
    with RecoveryCatalog(summary['catalog_path']) as catalog:
        statuses = {s['status']: s['count'] for s in catalog.statuses()}
        assert statuses['usable'] >= 14 and statuses['not_recovered'] == 2
        assert statuses['thumbnail_cache'] == 1 and statuses['suspect_damaged'] == 1
        assert statuses['deleted_usable'] == 2
        deleted = catalog.query(search='old_draft.pdf')
        assert deleted[0]['relative_path'] == '卷1-DATA/_已删除文件/Documents/old_draft.pdf'
        rows = catalog.query(search='report.pdf')
        assert rows[0]['relative_path'] == '卷1-DATA/Documents/report.pdf'
        catalog.set_selected([rows[0]['id']])
        exported = catalog.export_selected(tmp_path / 'export')
    assert exported['recovered'] == 1 and not exported['failed']
    files = [json.loads(l) for l in Path(exported['report']).read_text(encoding='utf-8').splitlines()]
    copied = [f for f in files if f.get('record') == 'file']
    assert copied[0]['export_status'] == 'copied-and-verified'
    expected = next(f['content'] for f in truth['files'] if f['path'] == 'Documents/report.pdf')
    assert (tmp_path / 'export' / copied[0]['output']).read_bytes() == expected
    reopened = reopen_workspace(tmp_path / 'job')
    assert reopened.count() == summary['row_count']
    reopened.close()


def test_continue_interrupted_auto_job_in_place(field, tmp_path):
    root, source, _ = field
    job = tmp_path / 'job'
    job.mkdir()
    (job / 'job_request.json').write_text(json.dumps(dict(tool='auto', source=str(source), output=str(job),
                                                          options=dict(reserve_mib=1))), encoding='utf-8')
    holder = {}
    engine = AutoRecovery(source, job / 'payload', dict(reserve_mib=1), cancel=lambda: holder['e'].ctx.stage == 'named_extract')
    holder['e'] = engine
    assert engine.run()['status'] == 'cancelled'
    runner = JobRunner()
    runner.start(JobSpec('auto', str(source), str(job), dict(reserve_mib=1, resume=True)))
    result = wait(runner)
    assert result.status == 'completed', (result.error, result.log[-3000:])
    assert json.loads((job / 'payload' / 'auto_manifest.json').read_text(encoding='utf-8'))['run'] == 2
    assert (job / 'job_request.json').is_file() and list(job.glob('job_request.resume-*.json'))
    with RecoveryCatalog(result.summary['catalog_path']) as catalog:
        assert catalog.count(status='usable') >= 14
    other = tmp_path / 'other.bin'
    other.write_bytes(b'x' * 4096)
    with pytest.raises(ValueError):
        validate_spec(JobSpec('auto', str(other), str(job), dict(resume=True)))


def test_result_import_streams_large_listings(field, tmp_path):
    root, source, _ = field
    job = tmp_path / 'job'
    payload = job / 'payload'
    (payload / '最终结果' / '可用').mkdir(parents=True)
    count = 5000
    with open(payload / '清单.jsonl', 'w', encoding='utf-8') as listing:
        for i in range(count):
            name = f'f{i}.txt'
            data = f'file {i}\n'.encode()
            (payload / '最终结果' / '可用' / name).write_bytes(data)
            listing.write(json.dumps(dict(volume='卷1', record=100 + i, original_path=f'docs/{name}', path_known=True,
                                          output=f'最终结果/可用/{name}', category='可用', category_en='usable',
                                          size=len(data), sha256=hashlib.sha256(data).hexdigest(), grade='usable',
                                          check='text_decodes_utf-8', map_methods=['anchor'], origin='rebuilt_block_map'),
                                     ensure_ascii=False) + '\n')
    (payload / '未恢复清单.jsonl').write_text('', encoding='utf-8')
    spec = JobSpec('auto', str(source), str(job), {})
    loaded = []
    import revivex_catalog
    original = revivex_catalog.RecoveryCatalog.ingest

    def spy(self, source_id, rows, *args, **kwargs):
        rows = list(rows)
        loaded.append(len(rows))
        return original(self, source_id, rows, *args, **kwargs)

    with patch.object(revivex_catalog.RecoveryCatalog, 'ingest', spy):
        result = collect_results(spec, 0)
    assert max(loaded) <= 2000 and sum(loaded) == count  # imported in bounded batches
    assert result.rows == [] and result.summary['rows_truncated'] is True
    with RecoveryCatalog(result.summary['catalog_path']) as catalog:
        assert catalog.count(status='usable') == count
        assert catalog.count(eligible_only=True) == count


# --- desktop UI ------------------------------------------------------------------
@pytest.fixture(scope='module')
def app():
    from PySide6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    from revivex_ui import MainWindow
    w = MainWindow(persist_settings=False)
    w.set_language('zh')
    yield w
    w.close()


def test_ui_passes_fast_temp_folder_and_validates_it(window, tmp_path):
    from revivex_ui import MainWindow
    src = tmp_path / 's.bin'
    src.write_bytes(b'x')
    out = tmp_path / 'out'
    out.mkdir()
    window.source.setText(str(src))
    window.output.setText(str(out))
    assert window.workdir_panel.isVisibleTo(window)
    window.workdir.setText(str(tmp_path))
    calls = []
    with patch.object(MainWindow, 'begin_job', lambda self, *a: calls.append(a)):
        window.start_scan()
    assert calls[0][0] == 'auto' and calls[0][3]['work_dir'] == str(tmp_path)
    window.workdir.setText(str(tmp_path / 'nope'))
    with patch.object(MainWindow, 'alert', lambda self, m: calls.append(('alert', m))), \
            patch.object(MainWindow, 'begin_job', lambda self, *a: calls.append(a)):
        window.start_scan()
    assert calls[-1] == ('alert', window.t('workdir_missing'))
    window.method.setCurrentIndex(1)
    assert not window.workdir_panel.isVisibleTo(window)


def test_ui_renders_item_stages_with_total(window, tmp_path):
    window.start_auto_progress(str(tmp_path))
    (tmp_path / 'progress.json').write_text(json.dumps(dict(
        stage='named_extract', stage_index=8, stage_count=11, unit='items', scanned_bytes=250, planned_bytes=1000,
        bytes_per_second=None, verified_files=200, candidates=1000, failed=3)), encoding='utf-8')
    window.poll_auto_progress()
    assert window.auto_stage_label.text() == '阶段 8/11 · 命名提取'
    assert window.auto_bytes_label.text() == '已处理 250 / 1000'
    assert (window.progress.maximum(), window.progress.value()) == (1000, 250)
    window.set_language('en')
    assert window.auto_stage_label.text() == 'Stage 8/11 · Extract named files'
    (tmp_path / 'progress.json').write_text(json.dumps(dict(stage='sample_probe', stage_index=2, stage_count=None,
                                                            unit='items', scanned_bytes=3, planned_bytes=None)))
    window.poll_auto_progress()
    assert window.auto_stage_label.text() == 'Stage 2 · Sample probe'
    window.stop_auto_progress()


def test_ui_continue_button_for_interrupted_auto_run(window, tmp_path):
    from revivex_ui import MainWindow
    job = tmp_path / 'job'
    job.mkdir()
    (job / 'job_request.json').write_text(json.dumps(dict(tool='auto', source='/x/src.vhdx', output=str(job),
                                                          options=dict(max_file_mib=7, work_dir='/fast'))))
    window.catalog = RecoveryCatalog(job / 'catalog.sqlite')
    window.run_summary = dict(tool='auto', scan_status='cancelled', manifests=[])
    window.refresh_results()
    assert window.resume_button.isEnabled()
    calls = []
    with patch.object(MainWindow, 'begin_job', lambda self, *a: calls.append(a)):
        window.resume_scan()
    assert calls == [('auto', '/x/src.vhdx', str(job), dict(max_file_mib=7, work_dir='/fast', resume=True))]
    window.run_summary = dict(tool='auto', scan_status='completed_scan', manifests=[dict(schema='revivex.auto-recovery', status='completed')])
    window.refresh_results()
    assert not window.resume_button.isEnabled()
    window.catalog.close()
    window.catalog = None


def test_ui_starts_automatic_recovery_and_shows_results(app, window, field, tmp_path):
    root, source, _ = field
    out = tmp_path / 'out'
    out.mkdir()
    window.source.setText(str(source))
    window.output.setText(str(out))
    window.method.setCurrentIndex(0)
    window.start_scan()
    assert window.runner is not None and window.job_tool == 'auto'
    assert window.auto_panel.isVisibleTo(window) and window.auto_timer.isActive()
    seen = set()
    deadline = time.monotonic() + 120
    while window.runner is not None:
        assert time.monotonic() < deadline, 'UI auto run timed out'
        app.processEvents()
        window.poll_auto_progress()
        if window.auto_progress:
            seen.add(window.auto_stage_label.text())
        window.poll_job()
        time.sleep(0.01)
    while window.worker is not None and window.worker.isRunning():
        app.processEvents()
    assert any(text.startswith('阶段 ') for text in seen), seen
    assert window.status.text() == window.t('complete')
    assert window.catalog is not None and window.catalog.count(status='usable') >= 14
    labels = [window.status_filter.itemText(i) for i in range(window.status_filter.count())]
    assert any(label.startswith('可用') for label in labels) and any(label.startswith('未恢复') for label in labels)


def test_open_workspace_of_a_command_line_run_builds_its_catalog(field, tmp_path):
    root, source, _ = field
    job = tmp_path / 'job'
    job.mkdir()
    (job / 'job_request.json').write_text(json.dumps(dict(tool='auto', source=str(source), output=str(job), options={})))
    AutoRecovery(source, job / 'payload', dict(reserve_mib=1)).run()  # as the worker would, without the app
    assert not (job / 'catalog.sqlite').exists()
    catalog = reopen_workspace(job)
    try:
        assert catalog.count(status='usable') >= 14 and catalog.count(status='deleted_usable') == 2
    finally:
        catalog.close()
