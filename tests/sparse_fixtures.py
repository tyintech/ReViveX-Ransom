"""Safely extend newly created synthetic files in per-test temporary directories.

Test code only: never use this helper for an evidence/source file. Windows
must mark the temporary fixture sparse before extending its logical size.
https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_sparse
"""
import ctypes
import os
from pathlib import Path
import stat
import tempfile
import unittest

FSCTL_SET_SPARSE = 0x000900C4


def _mark_sparse_windows(stream, *, kernel=None, get_osfhandle=None):
    if kernel is None:
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    if get_osfhandle is None:
        import msvcrt
        get_osfhandle = msvcrt.get_osfhandle
    ioctl = kernel.DeviceIoControl
    ioctl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                     ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                     ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
    ioctl.restype = ctypes.c_int
    returned = ctypes.c_uint32()
    # NULL input is explicitly documented as SetSparse=TRUE. Never clear it.
    ok = ioctl(get_osfhandle(stream.fileno()), FSCTL_SET_SPARSE,
               None, 0, None, 0, ctypes.byref(returned), None)
    if not ok:
        error = getattr(ctypes, 'get_last_error', lambda: 0)()
        raise unittest.SkipTest(f'Filesystem cannot mark test fixture sparse (Windows error {error}); no extension attempted')


def sparse_truncate(stream, size, *, temporary_root):
    """Extend only a small synthetic fixture under a caller-owned temp root.

Unsupported sparse storage skips the test before allocation. POSIX truncate
uses holes. The caller must supply its TemporaryDirectory/pytest tmp_path.
"""
    root = Path(temporary_root).absolute()
    system_temp = Path(tempfile.gettempdir()).resolve()
    path = Path(stream.name).absolute()
    if root == system_temp or not root.resolve().is_relative_to(system_temp):
        raise ValueError('A dedicated per-test temporary directory is required')
    if not path.resolve().is_relative_to(root.resolve()) or path == root:
        raise ValueError('Fixture is outside its per-test temporary directory')
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink fixtures are forbidden')
    if not stream.writable() or isinstance(size, bool) or not isinstance(size, int) or size < 0:
        raise ValueError('Writable fixture and nonnegative integer size required')
    stream.flush()
    info = os.fstat(stream.fileno())
    named = path.stat()
    if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError('Fixture must be the opened regular temporary file')
    if info.st_size > 64 * 1024 * 1024 or size < info.st_size:
        raise ValueError('Only small newly generated fixtures may be extended')
    if os.name == 'nt':
        _mark_sparse_windows(stream)
    elif os.name != 'posix':
        raise unittest.SkipTest('Sparse fixture extension is unsupported on this OS')
    stream.truncate(size)
