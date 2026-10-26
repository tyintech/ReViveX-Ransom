import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import sparse_fixtures as fixtures


def test_posix_sparse_extension_preserves_bytes(tmp_path):
    if os.name != 'posix':
        pytest.skip('POSIX hole semantics test')
    path = tmp_path / 'synthetic.bin'
    with path.open('x+b') as stream:
        stream.write(b'header')
        fixtures.sparse_truncate(stream, 1024 * 1024, temporary_root=tmp_path)
        stream.seek(0)
        assert stream.read(6) == b'header'
        stream.seek(1024 * 1024 - 1)
        assert stream.read(1) == b'\0'
    assert path.stat().st_size == 1024 * 1024


def test_windows_ioctl_uses_file_handle_and_null_input(tmp_path):
    calls = []
    def ioctl(*args):
        calls.append(args)
        return 1
    with (tmp_path / 'synthetic.bin').open('xb') as stream:
        fixtures._mark_sparse_windows(stream, kernel=SimpleNamespace(DeviceIoControl=ioctl),
                                      get_osfhandle=lambda fd: 0x123456789)
    args = calls[0]
    assert args[0] == 0x123456789  # no accidental 32-bit HANDLE truncation
    assert args[1] == fixtures.FSCTL_SET_SPARSE
    assert args[2:6] == (None, 0, None, 0)
    assert args[6] is not None and args[7] is None


def test_windows_ioctl_failure_explicitly_skips(tmp_path):
    def ioctl(*args):
        return 0
    with (tmp_path / 'synthetic.bin').open('xb') as stream:
        with pytest.raises(unittest.SkipTest, match='no extension attempted'):
            fixtures._mark_sparse_windows(stream, kernel=SimpleNamespace(DeviceIoControl=ioctl),
                                          get_osfhandle=lambda fd: 123)


def test_sparse_failure_never_truncates_large_fixture(tmp_path):
    path = tmp_path / 'synthetic.bin'
    with path.open('xb') as stream:
        stream.write(b'header')
        # Patch only the branch selector, preserving pathlib's actual host type.
        fake_os = SimpleNamespace(name='nt', fstat=os.fstat)
        with patch.object(fixtures, 'os', fake_os), patch.object(fixtures, '_mark_sparse_windows',
                side_effect=unittest.SkipTest('unsupported filesystem')):
            with pytest.raises(unittest.SkipTest):
                fixtures.sparse_truncate(stream, 1024**4, temporary_root=tmp_path)
    assert path.stat().st_size == 6


def test_outside_fixture_root_is_rejected(tmp_path):
    owned = tmp_path / 'owned'
    owned.mkdir()
    with (tmp_path / 'outside.bin').open('xb') as stream:
        with pytest.raises(ValueError, match='outside'):
            fixtures.sparse_truncate(stream, 1024**4, temporary_root=owned)


def test_windows_real_sparse_fixture_when_available(tmp_path):
    if os.name != 'nt':
        pytest.skip('Real Windows filesystem check')
    path = tmp_path / 'windows-synthetic.bin'
    with path.open('x+b') as stream:
        stream.write(b'header')
        fixtures.sparse_truncate(stream, 1024 * 1024, temporary_root=tmp_path)
        stream.seek(1024 * 1024 - 1)
        assert stream.read(1) == b'\0'
    assert path.stat().st_file_attributes & 0x200  # FILE_ATTRIBUTE_SPARSE_FILE
