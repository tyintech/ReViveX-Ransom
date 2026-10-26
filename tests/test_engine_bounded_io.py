"""Engines must never map, read_bytes() or fully hash large sources."""
import json
import mmap
import os
import pathlib
import sqlite3
import struct
import sys
from contextlib import closing
from unittest.mock import patch

import pytest

import carve_verified_formats
import salvage_zip
from carve_verified_formats import PNG_SIGNATURE, carve, parse_png, sqlite_extent
from recover_vhdx_resident import recover
from revivex_source_io import BoundedSource, MAX_SLICE, unpack_at
from test_carve_verified_formats import png
from test_recover_vhdx_resident import make_record

WINDOW = 8 * 1024 * 1024


@pytest.fixture
def forbid_whole_source():
    original = pathlib.Path.read_bytes

    def no_read_bytes(self):
        if self.name in ('disk.bin', 'sample.bin'):
            raise AssertionError('Path.read_bytes on source is forbidden')
        return original(self)
    with patch('mmap.mmap', side_effect=OSError(1450, 'Insufficient system resources')), \
            patch.object(pathlib.Path, 'read_bytes', no_read_bytes):
        yield


def make_sqlite(path):
    with closing(sqlite3.connect(path)) as database:
        database.execute('CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)')
        database.execute("INSERT INTO t VALUES (1, 'bounded')")
        database.commit()
    return path.read_bytes()


def test_carve_png_and_sqlite_without_mmap(tmp_path, forbid_whole_source):
    sqlite_bytes = make_sqlite(tmp_path / 'db.sqlite')
    image = png()
    source = tmp_path / 'disk.bin'
    source.write_bytes(b'pad' + image + b'mid' + sqlite_bytes)
    report = carve(source, tmp_path / 'out', 1 << 20, 1 << 20, 1 << 20)
    assert report['counts']['png_unique_outputs'] == 1
    assert report['counts']['sqlite_unique_outputs'] == 1
    assert report['source_hash_status'] == 'computed_full_source'
    assert report['source_sha256']


def test_carve_png_straddling_window_boundary(tmp_path, forbid_whole_source):
    image = png()
    start = WINDOW - 3  # signature split across the 8 MiB window edge
    data = bytearray(WINDOW + 4096)
    data[start:start + len(image)] = image
    source = tmp_path / 'disk.bin'
    source.write_bytes(data)
    report = carve(source, tmp_path / 'out', 1 << 20, 1 << 20, 1 << 20)
    assert report['counts']['png_unique_outputs'] == 1
    assert report['files'][0]['offset'] == start


def test_carve_large_source_skips_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(carve_verified_formats, 'FULL_HASH_LIMIT', 1024)
    source = tmp_path / 'disk.bin'
    source.write_bytes(b'x' * 2048 + png())
    report = carve(source, tmp_path / 'out', 1 << 20, 1 << 20, 1 << 20)
    assert report['source_sha256'] is None
    assert report['source_hash_status'] == 'skipped_large_source_stat_identity_only'
    verification = carve_verified_formats.verify_outputs(tmp_path / 'out', 'ab' * 32)
    assert verification['source_hash_matches_previous_scan'] is None
    assert verification['source_hash_comparison'].startswith('not_possible')


def test_parse_png_and_sqlite_extent_on_bounded_source(tmp_path):
    image = png()
    path = tmp_path / 'f.bin'
    path.write_bytes(b'zz' + image)
    with BoundedSource(path) as source:
        assert parse_png(source, 2, len(source), 1024) == parse_png(path.read_bytes(), 2, len(source), 1024)
    sqlite_bytes = make_sqlite(tmp_path / 'db.sqlite')
    with BoundedSource(tmp_path / 'db.sqlite') as source:
        assert sqlite_extent(source, 0, len(source)) == sqlite_extent(sqlite_bytes, 0, len(sqlite_bytes))


def test_resident_without_mmap(tmp_path, forbid_whole_source):
    source = tmp_path / 'sample.bin'
    source.write_bytes(b'\x00' * 512 + make_record())
    result = recover(source, tmp_path / 'rec')
    assert result['counts']['resident_streams'] == 1
    assert (tmp_path / 'rec' / result['files'][0]['output']).read_bytes() == b'verified test data'


def test_resident_record_after_window_boundary(tmp_path, forbid_whole_source):
    source = tmp_path / 'sample.bin'
    with source.open('wb') as stream:
        stream.truncate(WINDOW - 512)
        stream.seek(WINDOW - 512)
        stream.write(make_record())
    result = recover(source, tmp_path / 'rec')
    assert result['counts']['resident_streams'] == 1
    assert result['files'][0]['offset'] == WINDOW - 512


def test_salvage_zip_without_mmap(tmp_path, forbid_whole_source, monkeypatch):
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('a/hello.txt', b'hello bounded world' * 50)
    source = tmp_path / 'disk.bin'
    source.write_bytes(b'junk' + buffer.getvalue())
    out = tmp_path / 'out'
    monkeypatch.setattr(sys, 'argv', ['salvage_zip.py', str(source), str(out), '--memory-map'])
    salvage_zip.main()
    manifest = json.loads((out / '_salvage_manifest.json').read_text(encoding='utf-8'))
    assert manifest['recovered_files'] == 1
    assert manifest['input_hash_status'] == 'computed_full_input'
    assert (out / 'a' / 'hello.txt').read_bytes() == b'hello bounded world' * 50


def test_salvage_zip_large_input_skips_hash(tmp_path, monkeypatch):
    import io
    import zipfile
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        archive.writestr('x.txt', b'data')
    source = tmp_path / 'disk.bin'
    source.write_bytes(buffer.getvalue())
    monkeypatch.setattr(salvage_zip, 'FULL_HASH_LIMIT', 10)
    out = tmp_path / 'out'
    monkeypatch.setattr(sys, 'argv', ['salvage_zip.py', str(source), str(out)])
    salvage_zip.main()
    manifest = json.loads((out / '_salvage_manifest.json').read_text(encoding='utf-8'))
    assert manifest['input_sha256'] is None
    assert manifest['input_hash_status'] == 'skipped_large_source_stat_identity_only'
    assert manifest['recovered_files'] == 1


def test_bounded_source_find_across_window_and_limits(tmp_path):
    path = tmp_path / 'b.bin'
    data = bytearray(WINDOW + 100)
    data[WINDOW - 2:WINDOW + 2] = b'ABCD'
    path.write_bytes(data)
    with BoundedSource(path) as source:
        assert source.find(b'ABCD') == WINDOW - 2
        assert source.find(b'ABCD', 0, WINDOW + 1) == -1  # match would exceed end
        assert source.find(b'ABCD', WINDOW - 1) == -1
    # a source reporting a larger length rejects oversized slices
    with BoundedSource(path, length=MAX_SLICE * 2) as source:
        with pytest.raises(ValueError):
            source[0:MAX_SLICE + 1]


def test_unpack_at_matches_struct(tmp_path):
    raw = bytes(range(64))
    path = tmp_path / 'u.bin'
    path.write_bytes(raw)
    with BoundedSource(path) as source:
        for fmt, offset in (('<HH', 3), ('>I', 10), ('<Q', 20), ('<4s2H', 5)):
            assert unpack_at(fmt, source, offset) == struct.unpack_from(fmt, raw, offset)
            assert unpack_at(fmt, raw, offset) == struct.unpack_from(fmt, raw, offset)
        with pytest.raises(struct.error):
            unpack_at('<Q', source, 60)
