"""Automatic routing: valid VHDX -> logical index; no NTFS metadata -> raw carving."""
import json
import random

from field_fixtures import MiB, zip_bytes
from revivex_auto import AutoRecovery
from revivex_jobs import collect_results, JobSpec
from test_recover_vhdx_files import ntfs_fixture
from vhdx_fixtures import build_vhdx


def test_valid_mapping_uses_logical_index(tmp_path):
    data, _ = ntfs_fixture()
    source = build_vhdx(tmp_path / 'healthy.vhdx', data + bytes(MiB))
    progress = tmp_path / 'progress.json'
    manifest = AutoRecovery(source, tmp_path / 'job' / 'payload', dict(reserve_mib=1), progress_path=progress).run()
    assert manifest['status'] == 'completed' and manifest['route']['route'] == 'logical'
    assert manifest['sample_probe'] is None  # no sampling needed when the mapping validates
    final = json.loads(progress.read_text(encoding='utf-8'))
    assert final['stage_count'] == 3 and final['stage'] == 'done'
    result = collect_results(JobSpec('auto', str(source), str(tmp_path / 'job'), {}), 0)
    assert result.status == 'completed'
    names = {row['name'] for row in result.rows}
    assert 'report.bin' in names


def test_no_ntfs_metadata_falls_back_to_raw_carving(tmp_path):
    rng = random.Random(5)
    source = tmp_path / 'blob.bin'
    source.write_bytes(rng.randbytes(MiB) + zip_bytes(3, 4, 5000) + rng.randbytes(MiB))
    progress = tmp_path / 'progress.json'
    manifest = AutoRecovery(source, tmp_path / 'job' / 'payload', dict(reserve_mib=1), progress_path=progress).run()
    assert manifest['route']['route'] == 'raw' and manifest['status'] == 'completed'
    assert manifest['sample_probe']['verdict'] == 'no_ntfs_metadata_found'
    final = json.loads(progress.read_text(encoding='utf-8'))
    assert final['stage_count'] == 4 and final['scanned_bytes'] == final['planned_bytes'] == source.stat().st_size
    result = collect_results(JobSpec('auto', str(source), str(tmp_path / 'job'), {}), 0)
    recovered = [row for row in result.rows if row['status'] == 'recovered']
    assert len(recovered) == 1 and recovered[0]['integrity'].startswith('verified:')
