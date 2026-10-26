"""Bounded, read-only access to very large recovery sources.

Never maps, copies or hashes a whole source. Every read is an explicit
``read_at`` of a bounded length, so memory use is independent of source size
(17 TB evidence files included). On Windows the source handle is opened with
``FILE_SHARE_READ`` only: while ReViveX holds it, other processes cannot open
the file for writing, so the evidence cannot change underneath a long scan.
Stat identity is still re-checked; it is not a content hash.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import os
from pathlib import Path
import struct
import threading

MiB = 1024 * 1024
DEFAULT_BLOCK = 8 * MiB
MAX_SLICE = 256 * MiB
EVIDENCE_SAMPLE = 64 * 1024


class SourceChangedError(OSError):
    """The source stat or sampled evidence no longer matches the recorded identity."""


def _open_windows_deny_write(path):
    import ctypes
    import msvcrt
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    generic_read, share_read, open_existing, normal = 0x80000000, 0x1, 3, 0x80
    handle = create(str(path), generic_read, share_read, None, open_existing, normal, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        error = ctypes.get_last_error()
        if error == 32:  # ERROR_SHARING_VIOLATION: someone holds write access.
            raise PermissionError(error, 'Source is open for writing by another process; refusing to read a changing source', str(path))
        raise OSError(error, ctypes.FormatError(error).strip(), str(path))
    try:
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    except OSError:
        kernel.CloseHandle(handle)
        raise
    return os.fdopen(fd, 'rb', buffering=0)


def open_source_readonly(path, *, deny_write=True):
    """Open read-only. On Windows, also refuse concurrent writers (fails closed)."""
    path = Path(path)
    if os.name == 'nt' and deny_write:
        return _open_windows_deny_write(path)
    return path.open('rb', buffering=0)


def change_time_ns(path):
    """Last metadata/content change time in ns.

    POSIX: st_ctime. Windows: NTFS ChangeTime from GetFileInformationByHandleEx,
    because st_ctime there is the creation time and os.utime can restore
    LastWriteTime after a modification, while ChangeTime cannot be set that way.
    """
    if os.name != 'nt':
        return os.stat(path).st_ctime_ns
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                       wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    read_attributes, share_all, open_existing, backup_semantics = 0x80, 0x7, 3, 0x02000000
    handle = create(str(path), read_attributes, share_all, None, open_existing, backup_semantics, None)
    if handle in (None, wintypes.HANDLE(-1).value):
        raise OSError(ctypes.get_last_error(), 'Cannot read file change time', str(path))

    class FileBasicInfo(ctypes.Structure):
        _fields_ = [('CreationTime', ctypes.c_longlong), ('LastAccessTime', ctypes.c_longlong),
                    ('LastWriteTime', ctypes.c_longlong), ('ChangeTime', ctypes.c_longlong),
                    ('FileAttributes', wintypes.DWORD)]
    info = FileBasicInfo()
    try:
        get = kernel.GetFileInformationByHandleEx
        get.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        get.restype = wintypes.BOOL
        if not get(handle, 0, ctypes.byref(info), ctypes.sizeof(info)):  # FileBasicInfo
            raise OSError(ctypes.get_last_error(), 'Cannot read file change time', str(path))
    finally:
        kernel.CloseHandle(handle)
    return (info.ChangeTime - 116444736000000000) * 100


def stat_identity(stat):
    return dict(size=stat.st_size, mtime_ns=stat.st_mtime_ns, ctime_ns=stat.st_ctime_ns,
                device=stat.st_dev, inode=stat.st_ino)


def evidence_digest(stream, size, sample=EVIDENCE_SAMPLE):
    """SHA-256 of a few fixed small regions (head, tail, evenly spaced points).

    This is key-evidence comparison for resume, NOT a full-content hash.
    """
    digest = hashlib.sha256()
    points = sorted({0, max(0, size - sample), *(size * i // 8 for i in range(1, 8))})
    for offset in points:
        digest.update(struct.pack('<Q', offset))
        digest.update(_pread(stream, offset, min(sample, max(0, size - offset)), None))
    return dict(kind='sampled_regions_sha256_not_full_hash', sample_bytes=sample,
                offsets=points, sha256=digest.hexdigest())


def _pread(stream, offset, length, lock):
    if length <= 0:
        return b''
    if hasattr(os, 'pread'):
        parts, fd = [], stream.fileno()
        while length:
            piece = os.pread(fd, length, offset)
            if not piece:
                break
            parts.append(piece)
            offset += len(piece)
            length -= len(piece)
        return b''.join(parts)
    with lock if lock is not None else _NullLock():
        stream.seek(offset)
        parts = []
        while length:
            piece = stream.read(length)
            if not piece:
                break
            parts.append(piece)
            length -= len(piece)
        return b''.join(parts)


class _NullLock:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def unpack_at(fmt, source, offset):
    """``struct.unpack_from`` for bytes-like objects and BoundedSource alike."""
    size = struct.calcsize(fmt)
    data = source[offset:offset + size]
    if len(data) != size:
        raise struct.error(f'unpack requires {size} bytes at offset {offset}')
    return struct.unpack(fmt, data)


class BoundedSource:
    """Read-only, bytes-like view (len/slice/find) backed by bounded reads.

    Slices are limited to ``MAX_SLICE``; ``find`` searches in bounded windows.
    A small LRU cache serves repeated candidate reads. Thread-safe.
    """

    def __init__(self, path, *, cache_block=MiB, cache_blocks=32, deny_write=True, stream=None, length=None):
        self.path = Path(path)
        self._owns = stream is None
        self.stream = open_source_readonly(self.path, deny_write=deny_write) if stream is None else stream
        try:
            self.opened_stat = os.fstat(self.stream.fileno())
            self.identity = stat_identity(self.opened_stat)
            self.length = self.opened_stat.st_size if length is None else length
        except BaseException:
            if self._owns:
                self.stream.close()
            raise
        self.cache_block = cache_block
        self.cache_blocks = cache_blocks
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        self._io_lock = threading.Lock()
        self.stats = dict(sequential_bytes=0, candidate_bytes=0, cache_hits=0, cache_misses=0, reads=0)

    # --- identity -------------------------------------------------------
    def check_unchanged(self):
        """Raise SourceChangedError if handle or path stat differs from open time."""
        current = stat_identity(os.fstat(self.stream.fileno()))
        named = stat_identity(self.path.stat())
        for label, value in (('handle', current), ('path', named)):
            if value['size'] != self.identity['size'] or value['mtime_ns'] != self.identity['mtime_ns']:
                raise SourceChangedError(f'Source changed while open ({label} stat differs); refusing to continue')
        return True

    def evidence(self):
        return evidence_digest(self.stream, self.length)

    # --- raw reads ------------------------------------------------------
    def read_at(self, offset, length, *, kind='candidate'):
        if offset < 0 or length < 0:
            raise ValueError('Negative read range')
        length = max(0, min(length, self.length - offset))
        if length > MAX_SLICE:
            raise ValueError('Read exceeds bounded slice limit; read in pieces')
        data = _pread(self.stream, offset, length, self._io_lock)
        with self._lock:
            self.stats['reads'] += 1
            self.stats['sequential_bytes' if kind == 'sequential' else 'candidate_bytes'] += len(data)
        return data

    def readinto_at(self, offset, buffer):
        """Sequential-scan read into a caller buffer; returns bytes read."""
        view = memoryview(buffer)
        total = 0
        if hasattr(os, 'preadv'):
            while total < len(view):
                got = os.preadv(self.stream.fileno(), [view[total:]], offset + total)
                if not got:
                    break
                total += got
        else:
            with self._io_lock:
                self.stream.seek(offset)
                while total < len(view):
                    got = self.stream.readinto(view[total:])
                    if not got:
                        break
                    total += got
        with self._lock:
            self.stats['reads'] += 1
            self.stats['sequential_bytes'] += total
        return total

    def _cached(self, index):
        with self._lock:
            block = self._cache.get(index)
            if block is not None:
                self._cache.move_to_end(index)
                self.stats['cache_hits'] += 1
                return block
            self.stats['cache_misses'] += 1
        block = self.read_at(index * self.cache_block, self.cache_block)
        with self._lock:
            self._cache[index] = block
            while len(self._cache) > self.cache_blocks:
                self._cache.popitem(last=False)
        return block

    # --- bytes-like protocol -------------------------------------------
    def __len__(self):
        return self.length

    def __getitem__(self, item):
        if isinstance(item, int):
            if item < 0:
                item += self.length
            if not 0 <= item < self.length:
                raise IndexError('source index out of range')
            return self[item:item + 1][0]
        start, stop, step = item.indices(self.length)
        if step != 1:
            raise ValueError('Stepped source slices are unsupported')
        if stop <= start:
            return b''
        if stop - start > MAX_SLICE:
            raise ValueError('Slice exceeds bounded memory limit; read in pieces')
        if stop - start >= self.cache_block * 4:
            return self.read_at(start, stop - start)
        first, last = start // self.cache_block, (stop - 1) // self.cache_block
        parts = [self._cached(index) for index in range(first, last + 1)]
        joined = parts[0] if len(parts) == 1 else b''.join(parts)
        base = first * self.cache_block
        return joined[start - base:stop - base]

    def find(self, sub, start=0, end=None, *, window=DEFAULT_BLOCK):
        end = self.length if end is None else min(end, self.length)
        start = max(0, start)
        overlap = max(0, len(sub) - 1)
        position = start
        while position < end:
            stop = min(end, position + window)
            data = self.read_at(position, min(end, stop + overlap) - position)
            found = data.find(sub, 0, max(0, min(len(data), end - position)))
            if found >= 0 and position + found + len(sub) <= end:
                return position + found
            if stop >= end:
                return -1
            position = stop
        return -1

    def close(self):
        if self._owns:
            self.stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


class WindowedSource:
    """Serve reads from an in-memory scan block when possible, else from source.

    Lets validators re-use the 8 MiB block already read by the sequential scan,
    so small candidates (NTFS records, headers) cause no extra source I/O.
    """

    def __init__(self, source, base, data):
        self.source, self.base, self.data = source, base, data
        self.length = len(source)

    def __len__(self):
        return self.length

    def __getitem__(self, item):
        if isinstance(item, int):
            return self[item:item + 1][0]
        start, stop, step = item.indices(self.length)
        if step != 1:
            raise ValueError('Stepped source slices are unsupported')
        if self.base <= start and stop <= self.base + len(self.data):
            return bytes(self.data[start - self.base:stop - self.base])
        return self.source[start:stop]

    def find(self, sub, start=0, end=None, **kwargs):
        end = self.length if end is None else end
        local_end = self.base + len(self.data)
        if self.base <= start and end <= local_end:
            found = self.data.find(sub, start - self.base, end - self.base)
            return found + self.base if found >= 0 else -1
        return self.source.find(sub, start, end, **kwargs)


def iter_blocks(source, start, end, *, block=DEFAULT_BLOCK, overlap=4096):
    """Yield (offset, bytes) covering [start, end) with ``overlap`` trailing bytes.

    Candidate start offsets belong to the block whose [offset, offset+block)
    contains them, so overlap bytes are context only and never double-counted.
    """
    position = start
    while position < end:
        length = min(block, end - position)
        extra = min(overlap, max(0, source.length - position - length))
        buffer = bytearray(length + extra)
        got = source.readinto_at(position, buffer)
        if got < length:
            raise OSError(f'Short read at offset {position}: expected {length} bytes, got {got}')
        yield position, length, bytes(buffer[:got]) if got != len(buffer) else bytes(buffer)
        position += length


def free_space(path):
    import shutil
    path = Path(path)
    while not path.exists():
        path = path.parent
    return shutil.disk_usage(path).free
