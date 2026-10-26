from sparse_fixtures import sparse_truncate
import json
from diagnose_recovery_source import diagnose
from vhdx_fixtures import build_vhdx


def test_valid_container_diagnostic_is_not_payload_validation(tmp_path):
    source = build_vhdx(tmp_path / 'source.vhdx', b'X' * 512)
    result = diagnose(source)
    assert result['logical_mapping'] == 'validated_metadata_only'
    assert result['vhdx']['virtual_size'] == 512
    assert result['original_content_completeness'] == 'unknown'
    assert result['guest_payload_scanned'] is False
    assert result['full_image_hash_performed'] is False
    assert 'virtual_disk_id' not in json.dumps(result)


def test_diagnostic_reports_unknown_without_source_path(tmp_path):
    source = tmp_path / 'private-source.bin'
    data = b'not a disk' * 100
    source.write_bytes(data)
    result = diagnose(source)
    assert result['logical_mapping'] == 'unavailable'
    assert result['original_content_completeness'] == 'unknown'
    assert result['source_stat_unchanged'] is True
    assert str(source) not in json.dumps(result)
    assert source.read_bytes() == data


def test_marker_ranges_are_hypotheses_not_keys(tmp_path):
    source = tmp_path / 'large-looking.bin'
    body = 20 * 1024 * 1024
    with source.open('wb') as stream:
        sparse_truncate(stream, body, temporary_root=tmp_path)
        stream.seek(body)
        stream.write(b'--eph--' + b'A' * 43 + b'=\n--marker--GENTLEMEN\nGENTLEMEN--super--\n')
    result = diagnose(source)
    assert result['inferred_ranges_overlap_header_copies'] is True
    assert result['ransomware_marker']['identity_not_proven_by_marker'] is True
    assert 'ephemeral_public_key_hex' not in json.dumps(result)
    assert result['logical_mapping'] == 'unavailable'
    assert result['guest_payload_scanned'] is False
