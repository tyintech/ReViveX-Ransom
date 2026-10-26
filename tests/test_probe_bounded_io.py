from unittest.mock import patch
from probe_vhdx import inspect


def test_probe_does_not_require_whole_source_mapping(tmp_path):
    source = tmp_path / 'disk.bin'
    source.write_bytes(b'vhdxfile' + bytes(65536 - 8) + b'head')
    original = source.read_bytes()
    with patch('mmap.mmap', side_effect=OSError(1450, 'Insufficient system resources')):
        report = inspect(source)
    assert report['signatures']['vhdx'] == [{'offset': 0}]
    assert report['signatures']['header'] == [{'offset': 65536}]
    assert source.read_bytes() == original


def test_probe_finds_split_signature_once_and_caps_hits(tmp_path):
    boundary = 8 * 1024 * 1024
    source = tmp_path / 'disk.bin'
    data = bytearray(boundary + 4096)
    data[boundary - 3:boundary + 5] = b'vhdxfile'
    data[100:100 + 8 * 201] = b'EFI PART' * 201
    source.write_bytes(data)
    report = inspect(source)
    assert report['signatures']['vhdx'] == [{'offset': boundary - 3}]
    assert len(report['signatures']['gpt']) == 200
    assert 'gpt' in report['truncated_signatures']
