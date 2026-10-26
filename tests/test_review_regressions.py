"""Regressions for crash windows, per-file errors, unreadable sectors and cancel."""
import json
import os
import shutil
import time
from pathlib import Path

import pytest

from field_fixtures import MiB, build_field_case
from revivex_auto import AutoRecovery


@pytest.fixture(scope='module')
def done_case(tmp_path_factory):
    root = tmp_path_factory.mktemp('regress')
    source, truth = build_field_case(root)
    AutoRecovery(source, root / 'base', dict(reserve_mib=1)).run()
    return root, source


def copy_output(done_case, tmp_path):
    root, source = done_case
    output = tmp_path / 'out'
    shutil.copytree(root / 'base', output)
    return output


def listing(output):
    return [json.loads(l) for l in (output / '清单.jsonl').read_text(encoding='utf-8').splitlines()]


def test_pending_move_onto_someone_elses_file_is_not_marked_done(done_case, tmp_path):
    from revivex_named_extract import open_state
    from revivex_organize import organize, undo, write_manifests
    output = copy_output(done_case, tmp_path)
    state = open_state(output / '_state' / 'extract.sqlite')
    undo(state, output)
    vid, number, staged = state.execute("SELECT volume, number, staged FROM files WHERE status='extracted' LIMIT 1").fetchone()
    occupied = output / '最终结果' / 'occupied.bin'
    occupied.write_bytes(b'another file')
    with state:  # intent recorded, then "killed" before the move
        state.execute('INSERT INTO moves(volume, number, src, dst) VALUES(?,?,?,?)',
                      (vid, number, f'_提取暂存/{staged}', '最终结果/occupied.bin'))
    organize(state, output)
    final = state.execute('SELECT final FROM files WHERE volume=? AND number=?', (vid, number)).fetchone()[0]
    assert final != '最终结果/occupied.bin' and (output / final).is_file()
    assert occupied.read_bytes() == b'another file'
    write_manifests(state, output)
    state.close()
    assert all((output / e['output']).is_file() for e in listing(output))


def test_link_then_kill_window_is_reconciled(done_case, tmp_path):
    from revivex_named_extract import open_state
    from revivex_organize import organize, undo
    output = copy_output(done_case, tmp_path)
    state = open_state(output / '_state' / 'extract.sqlite')
    undo(state, output)
    vid, number, staged = state.execute("SELECT volume, number, staged FROM files WHERE status='extracted' LIMIT 1").fetchone()
    source = output / '_提取暂存' / staged
    target = output / '最终结果' / 'linked' / Path(staged).name
    target.parent.mkdir(parents=True)
    os.link(source, target)  # killed between link and unlink
    with state:
        state.execute('INSERT INTO moves(volume, number, src, dst) VALUES(?,?,?,?)',
                      (vid, number, f'_提取暂存/{staged}', target.relative_to(output).as_posix()))
    organize(state, output)
    assert not source.exists() and target.is_file()
    assert undo(state, output)['restored'] >= 1 and source.is_file()
    state.close()


def test_one_locked_file_does_not_stop_organizing(done_case, tmp_path, monkeypatch):
    import revivex_organize
    from revivex_named_extract import open_state
    output = copy_output(done_case, tmp_path)
    state = open_state(output / '_state' / 'extract.sqlite')
    revivex_organize.undo(state, output)
    original = revivex_organize.move_exclusive
    calls = {'n': 0}

    def locked(src, dst):
        calls['n'] += 1
        if calls['n'] == 2:
            raise PermissionError(13, 'file in use by another process')
        return original(src, dst)

    monkeypatch.setattr(revivex_organize, 'move_exclusive', locked)
    result = revivex_organize.organize(state, output)
    assert result['by_category']['move_errors'] == 1 and result['moved_now'] == len(listing(output)) - 1
    monkeypatch.setattr(revivex_organize, 'move_exclusive', original)
    again = revivex_organize.organize(state, output)  # the pending intent is completed next time
    assert state.execute("SELECT count(*) FROM files WHERE status='extracted' AND final IS NULL").fetchone()[0] == 0
    state.close()


def test_unreadable_sectors_are_recorded_and_skipped(done_case, tmp_path):
    from revivex_evidence import EvidenceScan, read_tolerant
    from revivex_source_io import BoundedSource
    root, source_path = done_case
    bad = (6 * MiB + 8192, 6 * MiB + 12288)
    with BoundedSource(source_path) as source:
        original = source.readinto_at

        def failing(offset, buffer):
            if offset < bad[1] and bad[0] < offset + len(buffer):
                raise OSError(23, 'data error (cyclic redundancy check)')
            return original(offset, buffer)

        source.readinto_at = failing
        data, unread = read_tolerant(source, 6 * MiB, MiB)
        assert unread == [list(bad)] and data[8192:12288] == b'\xff' * 4096 and data[:8192] == original_bytes(source_path, 6 * MiB, 8192)
        result = EvidenceScan(source, tmp_path / 'ev', block=MiB).run()
    assert result['status'] == 'finished' and result['unread'] == [list(bad)]


def original_bytes(path, offset, length):
    with open(path, 'rb') as handle:
        handle.seek(offset)
        return handle.read(length)


def test_promotion_requires_both_trusted_neighbours_to_agree():
    from revivex_block_map import Rebuilder, VolumeMap
    vmap = VolumeMap(1, 4096, 0, MiB, 0)
    for b in range(0, 60):  # a long linear run: interpolation tests exact up to distance 1
        vmap.blocks[b] = [100 * MiB + b * MiB, 'anchor', 1, 1, 1]
    vmap.blocks[70] = [500 * MiB, 'searched_verified', 3, 3, 1]
    vmap.blocks[72] = [900 * MiB, 'searched_verified', 3, 3, 1]
    vmap.blocks[71] = [100 * MiB + 71 * MiB, 'interpolated_bracketed', 0, 0, 1]  # anchors' linear guess
    del vmap.blocks[30]
    vmap.blocks[30] = [130 * MiB, 'interpolated_bracketed', 0, 0, 1]  # inside the verified run
    report = Rebuilder.__new__(Rebuilder).interpolation_accuracy([vmap])
    assert report['trusted_max_distance'] >= 1
    assert vmap.blocks[71][1] == 'interpolated_bracketed'  # neighbours 70/72 disagree: never promoted
    assert vmap.blocks[30][1] == 'interpolated_tested' and report['promoted_bracketed_blocks'] == 1


def test_ui_cancel_stops_cooperatively_and_writes_the_summary(done_case, tmp_path):
    from revivex_jobs import JobRunner, JobSpec
    root, source = done_case
    runner = JobRunner()
    runner.start(JobSpec('auto', str(source), str(tmp_path / 'job'), dict(reserve_mib=1)))
    runner.cancel()
    deadline = time.monotonic() + 60
    while runner.poll() is None:
        assert time.monotonic() < deadline
        time.sleep(0.05)
    result = runner.poll()
    assert result.status == 'cancelled'
    manifest = json.loads((tmp_path / 'job' / 'payload' / 'auto_manifest.json').read_text(encoding='utf-8'))
    assert manifest['status'] == 'cancelled'  # stopped at a safe point, not killed
