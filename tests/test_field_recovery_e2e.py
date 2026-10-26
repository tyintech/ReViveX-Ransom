"""End-to-end: a dynamic VHDX whose header, region tables, BAT and metadata are
destroyed, with two NTFS volumes, an embedded disk image and Gentlemen-style
inferred damage, is recovered under original names and folders.

Nothing about the layout is passed in: block size, partition offsets, cluster
size and damaged ranges are all inferred from evidence.
"""
import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from field_fixtures import MiB, build_field_case
from revivex_auto import AutoRecovery

STAGES = ['diagnose', 'sample_probe', 'evidence_scan', 'evidence_index', 'block_map', 'volume_membership',
          'block_match', 'named_extract', 'grading', 'organize']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def listing(output):
    return [json.loads(line) for line in (output / '清单.jsonl').read_text(encoding='utf-8').splitlines()]


def missing(output):
    return [json.loads(line) for line in (output / '未恢复清单.jsonl').read_text(encoding='utf-8').splitlines()]


def run(source, output, **kwargs):
    logs = []
    options = dict(reserve_mib=1, **kwargs.pop('options', {}))
    engine = AutoRecovery(source, output, options, progress_path=output.parent / f'{output.name}-progress.json',
                          log=logs.append, **kwargs)
    manifest = engine.run()
    return engine, manifest, logs


@pytest.fixture(scope='module')
def case(tmp_path_factory):
    root = tmp_path_factory.mktemp('field-case')
    source, truth = build_field_case(root)
    before = (sha(source.read_bytes()), source.stat().st_mtime_ns, source.stat().st_size)
    fast = root / 'fast-ssd'
    fast.mkdir()
    engine, manifest, logs = run(source, root / 'baseline', options=dict(work_dir=str(fast)))
    return dict(root=root, source=source, truth=truth, before=before, fast=fast, manifest=manifest, logs=logs,
                output=root / 'baseline')


def by_path(entries):
    return {(e['volume'].split('-', 1)[-1], e['original_path']): e for e in entries}


def test_source_is_never_modified(case):
    source = case['source']
    assert (sha(source.read_bytes()), source.stat().st_mtime_ns, source.stat().st_size) == case['before']
    assert case['manifest']['source_stat_unchanged'] is True


def test_route_and_inferred_geometry(case):
    manifest = case['manifest']
    assert manifest['status'] == 'completed', manifest['message']
    assert manifest['route']['route'] == 'rebuild'
    assert manifest['diagnostic_summary']['logical_mapping'] == 'unavailable'
    assert manifest['route']['damaged_ranges'] == [list(r) for r in case['truth']['damaged']]
    volumes = {v['label'].split('-', 1)[-1]: v for v in manifest['rebuild']['volumes']}
    assert set(volumes) == {'DATA', 'SYSTEM'}  # the disk image inside DATA is not a volume
    assert volumes['DATA']['partition_shift'] == 192 * 1024  # P mod B, never configured
    assert volumes['SYSTEM']['partition_shift'] == 0
    assert all(v['cluster_size'] == 4096 and v['block_size'] == MiB for v in volumes.values())
    match = manifest['rebuild']['block_match']
    assert match['by_method'].get('structure_verified', 0) >= 2  # big.zip's isolated middle blocks
    assert match['holdout']['wrong_slot_passed'] == 0


def test_every_reachable_file_recovered_with_original_name_and_path(case):
    output, truth = case['output'], case['truth']
    found = by_path(e for e in listing(output) if not e['deleted'])
    special = {truth['orphan'], truth['victim']}
    checked = 0
    live = [item for item in truth['files'] if not item['deleted']]
    for item in live:
        if item['volume'] == 'DATA' and item['number'] in special:
            continue
        entry = found[(item['volume'], item['path'])]
        assert entry['path_known'] is True
        data = (output / entry['output']).read_bytes()
        assert data == item['content'], item['path']
        assert entry['sha256'] == sha(item['content'])
        assert entry['output'].endswith(item['path'])
        checked += 1
    assert checked == len(live) - 2
    # Resident (in-MFT) files come straight from evidence.
    assert found[('DATA', 'Documents/notes.txt')]['origin'] == 'resident_mft_record'
    # A file spanning blocks found only by ZIP member CRC probes.
    assert 'structure_verified' in found[('DATA', 'Archive/big.zip')]['map_methods']


def test_strict_parent_sequence_paths(case):
    output, truth = case['output'], case['truth']
    entries = listing(output)
    orphan = [e for e in entries if e['record'] == truth['orphan'] and e['volume'].endswith('DATA')]
    assert len(orphan) == 1
    assert orphan[0]['original_path'].startswith('_上级目录名丢失_60') and orphan[0]['path_known'] is False
    assert orphan[0]['original_path'].endswith('/orphan.txt')
    assert not any(e['original_path'].startswith('reused.txt/') for e in entries)  # never borrowed


def test_embedded_image_records_do_not_leak(case):
    entries = listing(case['output'])
    names = {e['original_path'].rsplit('/', 1)[-1] for e in entries}
    assert not names & set(case['truth']['inner_names'])
    assert not any('InnerOnly' in e['original_path'] for e in entries)
    image = by_path(entries)[('DATA', 'Archive/disk.img')]
    assert image['category'] == '待确认'


def test_damaged_file_listed_not_written(case):
    output, truth = case['output'], case['truth']
    rows = [m for m in missing(output) if m['record'] == truth['victim']]
    assert len(rows) == 1 and rows[0]['original_path'] == 'Projects/victim.bin' and rows[0]['reason']
    assert not list(output.rglob('victim.bin'))


def test_grades_and_categories(case):
    found = by_path(listing(case['output']))
    assert found[('DATA', 'Photos/a.png')]['category'] == '可用'
    assert found[('DATA', 'Photos/b.jpg')]['category'] == '可用'
    assert found[('DATA', 'Documents/report.pdf')]['category'] == '可用'
    assert found[('DATA', 'Projects/Deep/state.sqlite')]['category'] == '可用'
    assert found[('DATA', 'Documents/broken.png')]['category'] == '疑似损坏'
    assert found[('DATA', 'Photos/unknown.bin')]['category'] == '待确认'
    assert found[('DATA', 'Photos/Thumbs.db')]['category'] == '缩略图缓存'
    final = case['output'] / '最终结果'
    assert {p.name for p in final.iterdir() if p.is_dir()} == {'可用', '待确认', '疑似损坏', '缩略图缓存', '已删除文件'}
    assert (final / '可用' / '卷2-SYSTEM' / 'Windows' / 'System32' / 'kernel_helper.dll').is_file()
    log = (final / '_整理记录.tsv').read_text(encoding='utf-8').splitlines()
    assert len(log) == len(listing(case['output']))


def test_work_folder_holds_intermediate_data(case):
    output, fast = case['output'], case['fast']
    work = Path(case['manifest']['work_dir'])
    assert work.parent == fast and (work / 'evidence' / 'records.bin').is_file()
    assert (work / 'index.sqlite').is_file() and (work / 'map.sqlite').is_file()
    assert not (output / '_work').exists()
    assert not any(p.suffix == '.bin' and p.parent.name == 'evidence' for p in output.rglob('*'))


def test_progress_reports_every_stage(case):
    seen = [line.split(': ', 1)[1] for line in case['logs'] if line.startswith('stage ')]
    assert seen == STAGES[1:]  # diagnose is reported through progress.json directly
    progress = json.loads((case['root'] / 'baseline-progress.json').read_text(encoding='utf-8'))
    assert progress['stage'] == 'done' and progress['stage_count'] == 11 and progress['status'] == 'completed'
    for key in ('stage_index', 'unit', 'scanned_bytes', 'planned_bytes', 'verified_files', 'candidates', 'failed'):
        assert key in progress


def test_completed_run_refuses_to_run_again_and_never_overwrites(case):
    before = {p: p.stat().st_mtime_ns for p in (case['output'] / '最终结果').rglob('*') if p.is_file()}
    with pytest.raises(ValueError):
        AutoRecovery(case['source'], case['output'], dict(reserve_mib=1)).run()
    after = {p: p.stat().st_mtime_ns for p in (case['output'] / '最终结果').rglob('*') if p.is_file()}
    assert before == after


def result_set(output):
    return sorted((e['volume'], e['original_path'], e['sha256'], e['category']) for e in listing(output))


@pytest.mark.parametrize('stage', ['sample_probe', 'evidence_scan', 'evidence_index', 'block_map', 'volume_membership',
                                   'block_match', 'named_extract', 'grading', 'organize'])
def test_cancel_at_each_stage_then_resume_in_place(case, tmp_path, stage):
    output = tmp_path / 'out'
    holder = {}
    cancel = lambda: holder['engine'].ctx.stage == stage
    engine = AutoRecovery(case['source'], output, dict(reserve_mib=1), cancel=cancel)
    holder['engine'] = engine
    manifest = engine.run()
    assert manifest['status'] == 'cancelled'
    engine2, manifest2, logs = run(case['source'], output)
    assert manifest2['status'] == 'completed', manifest2['message']
    assert manifest2['run'] == 2
    assert result_set(output) == result_set(case['output'])
    resumed = [line.split(': ', 1)[1] for line in logs if line.startswith('stage ')]
    assert stage in resumed
    if stage not in ('sample_probe', 'evidence_scan'):
        assert 'evidence_scan' not in resumed  # the long sequential scan is never repeated
    assert not list(output.rglob('*.__r*')), 'resume must not create duplicate copies'


def test_crash_during_extraction_is_reconciled(case, tmp_path, monkeypatch):
    import revivex_named_extract
    output = tmp_path / 'out'
    original = revivex_named_extract.NamedExtractor._record
    calls = {'n': 0}

    def flaky(self, row, commit=False):
        calls['n'] += 1
        if calls['n'] == 6:
            raise RuntimeError('simulated power loss after placing a file')
        return original(self, row, commit)

    monkeypatch.setattr(revivex_named_extract.NamedExtractor, '_record', flaky)
    with pytest.raises(RuntimeError):
        AutoRecovery(case['source'], output, dict(reserve_mib=1)).run()
    monkeypatch.setattr(revivex_named_extract.NamedExtractor, '_record', original)
    engine, manifest, logs = run(case['source'], output)
    assert manifest['status'] == 'completed'
    assert result_set(output) == result_set(case['output'])
    assert not list(output.rglob('*.__r*'))


def test_organize_undo_and_redo(case, tmp_path):
    from revivex_organize import main as organize_main
    output = tmp_path / 'copy'
    shutil.copytree(case['output'], output)
    final_files = sorted(p for p in (output / '最终结果').rglob('*') if p.is_file() and not p.name.startswith('_'))
    assert organize_main([str(output), '--undo']) == 0
    assert not [p for p in (output / '最终结果').rglob('*') if p.is_file() and not p.name.startswith('_')]
    staged = [p for p in (output / '_提取暂存').rglob('*') if p.is_file()]
    assert len(staged) == len(final_files)
    assert (output / '最终结果' / '_撤回记录.tsv').is_file()
    assert organize_main([str(output)]) == 0
    again = sorted(p for p in (output / '最终结果').rglob('*') if p.is_file() and not p.name.startswith('_'))
    assert [p.relative_to(output) for p in again] == [p.relative_to(output) for p in final_files]
    assert result_set(output) == result_set(case['output'])


def test_files_damaged_by_an_unclean_stop_are_rechecked_and_rewritten(case, tmp_path, monkeypatch):
    import revivex_named_extract
    output = tmp_path / 'out'
    original = revivex_named_extract.NamedExtractor._record
    calls = {'n': 0}

    def crash(self, row, commit=False):
        calls['n'] += 1
        if calls['n'] == 12:
            raise RuntimeError('simulated OS crash')
        return original(self, row, commit)

    monkeypatch.setattr(revivex_named_extract.NamedExtractor, '_record', crash)
    with pytest.raises(RuntimeError):
        AutoRecovery(case['source'], output, dict(reserve_mib=1)).run()
    monkeypatch.setattr(revivex_named_extract.NamedExtractor, '_record', original)
    state = revivex_named_extract.open_state(output / '_state' / 'extract.sqlite')
    staged = state.execute("SELECT staged FROM files WHERE status='extracted' AND origin='rebuilt_block_map' LIMIT 1").fetchone()[0]
    state.close()
    damaged = output / '_提取暂存' / staged
    damaged.write_bytes(damaged.read_bytes()[:10])  # data the OS never flushed before the crash
    engine, manifest, logs = run(case['source'], output)
    assert manifest['status'] == 'completed'
    assert manifest['rebuild']['named_extract']['rechecked_after_unclean_stop'] == 1
    assert len((output / '_中断损坏输出' / '_提取暂存' / staged).read_bytes()) == 10  # moved aside, not deleted
    assert result_set(output) == result_set(case['output'])
    assert not list(output.rglob('*.__r*'))


def test_deleted_files_recovered_only_when_their_clusters_are_free(case):
    output, truth = case['output'], case['truth']
    deleted = {e['original_path']: e for e in listing(output) if e['deleted']}
    contents = {f['path']: f['content'] for f in truth['files'] if f['deleted']}
    for path in ('Documents/old_draft.pdf', 'Documents/tmp_note.txt'):
        entry = deleted[path]
        assert entry['category'] == '已删除文件/可用' and entry['category_en'] == 'deleted_usable'
        assert entry['output'].startswith('最终结果/已删除文件/可用/卷1-DATA/Documents/')
        assert (output / entry['output']).read_bytes() == contents[path]
    assert 'Photos/gone.jpg' not in deleted  # its clusters now hold Photos/a.png
    refused = [m for m in missing(output) if m['record'] == truth['reused_deleted']]
    assert refused[0]['deleted'] is True and refused[0]['reason'] == 'deleted_clusters_reused_by_existing_file'
    live = by_path(e for e in listing(output) if not e['deleted'])
    assert ('DATA', 'Documents/old_draft.pdf') not in live  # never mixed with live files
    totals = case['manifest']['rebuild']['totals']['deleted']
    assert totals['extracted'] == 2 and totals['not_extracted'] == 1


def test_skip_deleted_option(case, tmp_path):
    engine, manifest, logs = run(case['source'], tmp_path / 'out', options=dict(skip_deleted=True))
    assert not any(e['deleted'] for e in listing(tmp_path / 'out'))
    assert not any(m['deleted'] for m in missing(tmp_path / 'out'))
