"""Automatic read-only recovery: diagnose, route, recover, verify.

Routes (decided once, recorded, kept on resume):
- ``logical``: the VHDX mapping validates -> logical NTFS metadata index.
- ``rebuild``: the mapping is unavailable but a short sample probe finds
  plaintext NTFS metadata -> rebuild the block map from evidence and recover
  files under their original names (see revivex_rebuild.py).
- ``raw``: neither -> signature carving (no original names).

The raw route runs when the
mapping is unavailable or has known gaps: ONE sequential bounded-read pass
(8 MiB blocks) matches every supported signature at once (ZIP local header,
512-aligned NTFS FILE record, PNG, SQLite). Candidate discovery and content
validation are separate; candidates are not recovered files. ZIP candidates
are walked in source order so a verified archive is kept whole; damaged
archives fall back to member salvage (stage 4) of independently CRC-verified
members only. Results, provenance and checkpoints live in SQLite on the
output disk; the checkpoint advances only after results are durable.

The source is never written, mapped whole, copied whole or hashed whole.
Output hashes prove output bytes only, never original completeness/safety.
"""
from __future__ import annotations

import argparse
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
import errno
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import struct
import threading
import time
import zlib

from revivex_source_io import (BoundedSource, WindowedSource, SourceChangedError, DEFAULT_BLOCK,
                               free_space, unpack_at, stat_identity)
from revivex_stage import Cancelled, StageContext, StopRun

SCHEMA = 'revivex.auto-recovery'
SCHEMA_VERSION = 1
MiB = 1024 * 1024
GiB = 1024 * MiB
OVERLAP = 64 * 1024
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
SQLITE_SIGNATURE = b'SQLite format 3\x00'
ZIP_LOCAL = b'PK\x03\x04'
SIGNATURES = (('zip', ZIP_LOCAL), ('ntfs', b'FILE'), ('png', PNG_SIGNATURE), ('sqlite', SQLITE_SIGNATURE))
DEFAULTS = dict(max_file_mib=4096, max_total_mib=16 * 1024 * 1024, max_scan_bytes=None, scan_start=0,
                deep_raw=False, workers=2, block_mib=8, reserve_mib=4096, max_diagnostic_rows=200000,
                max_decoded_mib=256, work_dir=None, damaged_ranges=(), block_size_mib=None, route='auto',
                sample_count=256, match_missing_blocks=True, skip_deleted=False)
# Options that change what is scanned or how the map is built; a resume must keep them.
STRUCTURAL_OPTIONS = ('scan_start', 'max_scan_bytes', 'block_mib', 'damaged_ranges', 'block_size_mib', 'route')
ROUTES = ('auto', 'logical', 'rebuild', 'raw')
OPTION_KEYS = set(DEFAULTS)
STOP_STATUSES = ('cancelled', 'source_changed', 'source_read_error', 'output_space_low', 'output_limit', 'failed')
WARNING = ('Automatic salvage, not decryption or disk repair. Candidates are not recovered files. '
           'Only contiguous, independently verifiable content is saved; output hashes prove output '
           'bytes only, not original completeness or safety. Never execute recovered files.')


REBUILD_LIMITATIONS = [
    'The block map is rebuilt from evidence (INDX anchors, file headers, structure probes); a file is written only when every block it uses has trusted evidence.',
    'Files whose MFT record or data lies in an encrypted or unreadable range are listed in 未恢复清单.jsonl, not written.',
    'Grades are structure checks only; they do not prove original content, completeness or safety.',
    'NTFS compression/EFS, 4 KiB FILE records and NTFS 3.0 records are not supported.',
    'Inferred ransomware ranges are hypotheses from the file footer; they are scanned, never silently skipped.',
    'Source identity is stat plus sampled regions; no full-source content hash was computed.']
RESULT_README = """ReViveX 自动恢复结果 / automatic recovery results

最终结果/可用        结构校验通过的文件 (usable: full structure check passed)
最终结果/待确认      无可用格式校验或校验较弱，需要人工确认 (needs review)
最终结果/疑似损坏    结构校验失败，内容可能有误 (suspect damaged)
最终结果/缩略图缓存  Windows Thumbs.db 缩略图缓存 (thumbnail caches)
最终结果/已删除文件  NTFS 已删除、数据簇未被占用的文件，同样分级 (deleted files, graded the same way)
清单.jsonl          每个已写出文件：原始路径、输出位置、大小、SHA-256、分级
未恢复清单.jsonl     未写出的文件及原因（如块映射缺失、位于加密区）
最终结果/_整理记录.tsv 每次移动的记录；用 revivex_organize.py --undo <本目录> 可全部撤回 (undo all moves)

校验只说明文件结构，不证明内容与原件一致或文件安全。请勿直接运行恢复出的程序、脚本或宏。
Checks prove structure only, never authenticity or safety. Never run recovered programs, scripts or macros.
"""


class StopScan(Exception):
    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _no_symlinks(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink paths are not accepted')
    return path


def normalize_options(options):
    options = dict(options or {})
    unknown = set(options) - OPTION_KEYS
    if unknown:
        raise ValueError(f'Unknown auto-recovery options: {sorted(unknown)}')
    result = dict(DEFAULTS, **{k: v for k, v in options.items() if v is not None})
    for key in ('max_file_mib', 'max_total_mib', 'workers', 'block_mib', 'reserve_mib', 'max_diagnostic_rows', 'max_decoded_mib'):
        if not isinstance(result[key], int) or isinstance(result[key], bool) or result[key] <= 0:
            raise ValueError(f'{key} must be a positive integer')
    if result['max_scan_bytes'] is not None and (not isinstance(result['max_scan_bytes'], int) or result['max_scan_bytes'] <= 0):
        raise ValueError('max_scan_bytes must be a positive integer')
    if not isinstance(result['scan_start'], int) or result['scan_start'] < 0 or result['scan_start'] % 512:
        raise ValueError('scan_start must be a nonnegative multiple of 512')
    if not 1 <= result['workers'] <= 8 or not 1 <= result['block_mib'] <= 64:
        raise ValueError('workers must be 1..8 and block_mib 1..64')
    result['deep_raw'] = bool(result['deep_raw'])
    result['match_missing_blocks'] = bool(result['match_missing_blocks'])
    result['skip_deleted'] = bool(result['skip_deleted'])
    if result['route'] not in ROUTES:
        raise ValueError(f'route must be one of {ROUTES}')
    ranges = []
    for item in result['damaged_ranges'] or ():
        if isinstance(item, str):
            item = item.replace(':', '-').split('-')
        start, end = (int(v) for v in item)
        if start < 0 or end <= start:
            raise ValueError('damaged_ranges entries must be START-END byte offsets with END > START')
        ranges.append([start, end])
    result['damaged_ranges'] = sorted(ranges)
    if result['block_size_mib'] is not None and result['block_size_mib'] not in (1, 2, 4, 8, 16, 32, 64, 128, 256):
        raise ValueError('block_size_mib must be a power of two from 1 to 256')
    if result['work_dir'] is not None:
        result['work_dir'] = str(Path(result['work_dir']).absolute())
    return result


def peak_memory_bytes():
    try:
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                            ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                            ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                            ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                            ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
            counters = Counters()
            counters.cb = ctypes.sizeof(Counters)
            psapi = ctypes.WinDLL('psapi')
            process = ctypes.windll.kernel32.GetCurrentProcess()
            psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
            if psapi.GetProcessMemoryInfo(process, ctypes.byref(counters), counters.cb):
                return int(counters.PeakWorkingSetSize)
            return None
        import resource
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(peak if os.uname().sysname == 'Darwin' else peak * 1024)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Durable state
# ---------------------------------------------------------------------------
class AutoState:
    """SQLite results/checkpoint store; single writer (the scan thread)."""

    def __init__(self, path):
        self.path = Path(path)
        self.db = sqlite3.connect(str(self.path), isolation_level=None, check_same_thread=False)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA trusted_schema=OFF')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY, run INTEGER NOT NULL, kind TEXT NOT NULL,
            offset INTEGER NOT NULL, sub TEXT NOT NULL DEFAULT '', status TEXT NOT NULL, name TEXT NOT NULL DEFAULT '',
            relative_path TEXT NOT NULL DEFAULT '', output TEXT NOT NULL DEFAULT '', size INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL DEFAULT '', detail TEXT NOT NULL DEFAULT '{}', UNIQUE(kind, offset, sub));
        CREATE TABLE IF NOT EXISTS contents(sha256 TEXT PRIMARY KEY, run INTEGER NOT NULL, output TEXT NOT NULL, size INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS unscanned(start INTEGER NOT NULL, end INTEGER NOT NULL, run INTEGER NOT NULL, reason TEXT NOT NULL);
        ''')

    def get(self, key, default=None):
        row = self.db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put_many(self, values):
        self.db.executemany('INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                            [(k, _json(v)) for k, v in values.items()])

    def put(self, key, value):
        with self.transaction():
            self.put_many({key: value})

    def transaction(self):
        state = self

        class _Tx:
            def __enter__(self):
                state.db.execute('BEGIN IMMEDIATE')

            def __exit__(self, kind, value, tb):
                state.db.execute('COMMIT' if kind is None else 'ROLLBACK')
                return False
        return _Tx()

    def content_output(self, sha256):
        row = self.db.execute('SELECT output, run FROM contents WHERE sha256=?', (sha256,)).fetchone()
        return row

    def close(self):
        try:
            self.db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        except sqlite3.Error:
            pass
        self.db.close()


# ---------------------------------------------------------------------------
# Output staging (validators write temp files; scan thread dedups + places)
# ---------------------------------------------------------------------------
class Staging:
    def __init__(self, root):
        self.root = root
        self.dir = root / '.staging'
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._counter = 0

    def new(self):
        with self._lock:
            self._counter += 1
            return self.dir / f'{os.getpid()}-{threading.get_ident()}-{self._counter}.part'


class StreamWriter:
    """Exclusive-create temp file + streaming SHA-256; fsync on close."""

    def __init__(self, staging):
        self.path = staging.new()
        self.file = self.path.open('xb')
        self.hash = hashlib.sha256()
        self.size = 0

    def write(self, data):
        self.file.write(data)
        self.hash.update(data)
        self.size += len(data)

    def finish(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        self.file.close()
        return self.path, self.hash.hexdigest(), self.size

    def abort(self):
        try:
            self.file.close()
        finally:
            try:
                self.path.unlink()
            except OSError:
                pass


def _copy_range(source, start, end, writer, chunk=MiB):
    position = start
    while position < end:
        piece = source[position:min(end, position + chunk)]
        if not piece:
            raise OSError(f'Short read at {position}')
        writer.write(piece)
        position += len(piece)


_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$', re.I)


def safe_component(name, limit=120):
    name = _UNSAFE.sub('_', str(name)).strip().rstrip(' .')
    name = name.encode('utf-8')[:limit].decode('utf-8', errors='ignore').rstrip(' .') or 'unnamed'
    if _RESERVED.match(name.split('.')[0]):
        name = '_' + name
    return name


def shard(offset):
    return f'{offset // GiB:06d}G'


# ---------------------------------------------------------------------------
# Validators. Each returns a list of row dicts; staged outputs carry 'staged'.
# ---------------------------------------------------------------------------
def validate_png(src, offset, limits, staging):
    from carve_verified_formats import parse_png
    limit = min(len(src), offset + limits['max_file'])
    try:
        end, details = parse_png(src, offset, limit, limits['max_decoded'])
    except (ValueError, zlib.error, struct.error, IndexError) as error:
        return [dict(kind='png', offset=offset, status='rejected', name=f'{offset}.png', detail=dict(error=str(error)[:300]))]
    writer = StreamWriter(staging)
    try:
        _copy_range(src, offset, end, writer)
        staged = writer.finish()
    except BaseException:
        writer.abort()
        raise
    return [dict(kind='png', offset=offset, status='recovered', name=f'{offset}.png',
                 relative_path=f'png/{shard(offset)}/{offset}.png', staged=staged,
                 detail=dict(details, validation='png_chunk_crc_zlib_scanlines'))]


def validate_sqlite(src, offset, limits, staging):
    from carve_verified_formats import sqlite_extent, verify_sqlite
    limit = min(len(src), offset + limits['max_file'])
    try:
        end, details = sqlite_extent(src, offset, limit)
    except (ValueError, struct.error, IndexError) as error:
        return [dict(kind='sqlite', offset=offset, status='rejected', name=f'{offset}.sqlite', detail=dict(error=str(error)[:300]))]
    writer = StreamWriter(staging)
    try:
        _copy_range(src, offset, end, writer)
        path, digest, size = writer.finish()
    except BaseException:
        writer.abort()
        raise
    try:
        details.update(verify_sqlite(path))
    except (ValueError, sqlite3.DatabaseError, OSError) as error:
        path.unlink()
        return [dict(kind='sqlite', offset=offset, status='rejected', name=f'{offset}.sqlite',
                     detail=dict(details, error=str(error)[:300]))]
    for suffix in ('-journal', '-wal', '-shm'):
        extra = Path(str(path) + suffix)
        if extra.exists():
            extra.unlink()
    return [dict(kind='sqlite', offset=offset, status='recovered', name=f'{offset}.sqlite',
                 relative_path=f'sqlite/{shard(offset)}/{offset}.sqlite', staged=(path, digest, size),
                 detail=dict(details, validation='sqlite_header_extent_integrity_check'))]


def validate_ntfs_batch(window, offsets, limits, staging):
    """Validate 512-aligned FILE records inside one scan block (no extra I/O)."""
    from recover_vhdx_resident import parse_record, file_names, attributes
    rows, counts = [], Counter()
    for offset in offsets:
        raw = window[offset:offset + 1024]
        try:
            record, flags = parse_record(raw)
            links = file_names(record)
        except Exception:
            counts['ntfs_invalid_records'] += 1
            continue
        counts['ntfs_valid_records'] += 1
        chosen = min(links, key=lambda link: ({1: 0, 3: 1, 0: 2, 2: 3}.get(link['namespace'], 4), link['name'])) if links else None
        name = chosen['name'] if chosen else 'unnamed'
        directory = bool(flags & 2)
        if directory:
            counts['ntfs_directory_records'] += 1
            continue
        names = [dict(name=l['name'], parent_record=l['parent_record'], namespace=l['namespace']) for l in links[:8]]
        base = dict(record_number=struct.unpack_from('<I', record.data, 44)[0], in_use=bool(flags & 1), file_names=names)
        for position, kind, attr in attributes(record.data):
            if kind != 0x80:
                continue
            name_length, name_offset = struct.unpack_from('<BH', attr, 9)
            stream = attr[name_offset:name_offset + name_length * 2].decode('utf-16le', errors='replace') if name_length else ''
            sub = f'a{position}'
            display = name + (f':{stream}' if stream else '')
            if attr[8]:
                counts['ntfs_nonresident_streams'] += 1
                rows.append(dict(kind='ntfs', offset=offset, sub=sub, status='unsupported', name=display,
                                 detail=dict(base, stream_name=stream, reason='nonresident_stream_requires_validated_mapping')))
                continue
            if struct.unpack_from('<H', attr, 12)[0] & 0xC001:
                counts['ntfs_unsupported_flags'] += 1
                rows.append(dict(kind='ntfs', offset=offset, sub=sub, status='unsupported', name=display,
                                 detail=dict(base, stream_name=stream, reason='compressed_or_encrypted_or_sparse_attribute')))
                continue
            size, start = struct.unpack_from('<IH', attr, 16)
            data = attr[start:start + size]
            if not data:
                counts['ntfs_empty_streams'] += 1
                continue
            writer = StreamWriter(staging)
            try:
                writer.write(data)
                staged = writer.finish()
            except BaseException:
                writer.abort()
                raise
            folder = 'in_use' if flags & 1 else 'deleted_records'
            filename = safe_component(display.replace(':', '__stream_'))
            rows.append(dict(kind='ntfs', offset=offset, sub=sub, status='recovered', name=display,
                             relative_path=f'ntfs_resident/{folder}/{shard(offset)}/{offset}_{position}_{filename}',
                             staged=staged, detail=dict(base, stream_name=stream, validation='ntfs_fixup_attribute_bounds_resident_stream',
                                                        content_checksum='none_available')))
    return rows, counts


# --- ZIP --------------------------------------------------------------------
class ZipError(ValueError):
    pass


def _zip_descriptor(src, end, compressed, size, zip64):
    position = end + 4 if src[end:end + 4] == b'PK\x07\x08' else end
    for fmt in (('<IQQ', '<III') if zip64 else ('<III', '<IQQ')):
        length = struct.calcsize(fmt)
        if position + length > len(src):
            continue
        crc, cs, us = unpack_at(fmt, src, position)
        if cs == compressed and us == size:
            return crc, position + length
    raise ZipError('missing or mismatched data descriptor')


def _stream_member(src, start, compressed, method, max_size, sink=None, unknown_size=False):
    """CRC/length over a member without retaining it; optional streaming sink."""
    crc, total, position = 0, 0, start
    if method == 0:
        if compressed > max_size:
            raise ZipError('member exceeds file size limit')
        end = start + compressed
        if end > len(src):
            raise ZipError('member extent beyond source')
        while position < end:
            piece = src[position:min(end, position + MiB)]
            crc = zlib.crc32(piece, crc)
            if sink:
                sink.write(piece)
            position += len(piece)
        return end, crc, compressed
    decoder = zlib.decompressobj(-15)
    limit = len(src) if unknown_size else start + compressed
    if unknown_size:
        limit = min(limit, start + max_size + MiB)  # bounded search for the stream end
    while position < limit:
        piece = src[position:min(limit, position + MiB)]
        out = decoder.decompress(piece, max_size - total + 1)
        total += len(out)
        if total > max_size or decoder.unconsumed_tail:
            raise ZipError('member exceeds decompression size limit')
        crc = zlib.crc32(out, crc)
        if sink and out:
            sink.write(out)
        consumed = len(piece) - len(decoder.unused_data)
        position += consumed
        if decoder.eof:
            if not unknown_size and position != limit:
                raise ZipError('deflate trailing data')
            return position, crc, total
        if consumed == 0:
            break
    raise ZipError('incomplete deflate stream')


def _local_member(src, offset, max_size, sink=None):
    from salvage_zip import getname, zip64_sizes, stored_descriptor
    if offset + 30 > len(src):
        raise ZipError('truncated local header')
    _, version, flags, method, _, _, crc, cs, us, nl, xl = unpack_at('<4s5H3I2H', src, offset)
    if not 1 <= nl <= 4096 or version > 63:
        raise ZipError('implausible local header')
    raw, extra = src[offset + 30:offset + 30 + nl], src[offset + 30 + nl:offset + 30 + nl + xl]
    data_start = offset + 30 + nl + xl
    info = dict(header_offset=offset, flags=flags, method=method, version=version)
    if flags & 0x41 or flags & 0x2000:
        raise ZipError('encrypted member (no key; not decryptable)')
    if method not in (0, 8):
        raise ZipError(f'unsupported compression method {method}')
    try:
        name = getname(raw, flags, extra)
    except (ValueError, UnicodeError):
        name = None
        info['unsafe_or_undecodable_name'] = raw[:200].hex()
    info['name'] = name
    if flags & 8:
        if method == 8:
            end, actual_crc, size = _stream_member(src, data_start, 0, 8, max_size, sink, unknown_size=True)
            expected_crc, next_offset = _zip_descriptor(src, end, end - data_start, size, version >= 45)
            compressed = end - data_start
        else:
            data, end, expected_crc, compressed, size = stored_descriptor(src, data_start, max_size, version >= 45)
            actual_crc = zlib.crc32(data)
            if sink:
                sink.write(data)
            _, next_offset = _zip_descriptor(src, end, compressed, size, version >= 45)
    else:
        compressed, size = zip64_sizes(cs, us, extra)
        if size > max_size:
            raise ZipError('member exceeds file size limit')
        end, actual_crc, actual = _stream_member(src, data_start, compressed, method, max_size, sink)
        if actual != size:
            raise ZipError('uncompressed size mismatch')
        expected_crc, next_offset = crc, end
    if actual_crc != expected_crc:
        raise ZipError('CRC-32 mismatch')
    info.update(data_start=data_start, data_end=end, next_offset=next_offset, crc32=f'{expected_crc:08x}',
                compressed_size=compressed, size=size, directory=bool(name and name.endswith('/')))
    return info


def _central_directory(src, start, members, position, max_entries):
    """Validate CD entries + EOCD against walked local members. Returns end."""
    entries = []
    while src[position:position + 4] == b'PK\x01\x02':
        if len(entries) >= max_entries:
            raise ZipError('central directory entry limit')
        values = unpack_at('<4s6H3I5H2I', src, position)
        _, _, _, flags, method, _, _, crc, cs, us, nl, xl, cl, _, _, _, local = values
        entries.append(dict(crc=crc, cs=cs, us=us, local=local, raw=src[position + 46:position + 46 + nl], method=method))
        position += 46 + nl + xl + cl
    if src[position:position + 4] == b'PK\x06\x06':
        size = unpack_at('<Q', src, position + 4)[0]
        position += 12 + size
        if src[position:position + 4] == b'PK\x06\x07':
            position += 20
    if src[position:position + 4] != b'PK\x05\x06':
        raise ZipError('end of central directory not found where expected')
    comment = unpack_at('<H', src, position + 20)[0]
    end = position + 22 + comment
    if end > len(src):
        raise ZipError('EOCD comment beyond source')
    if len(entries) != len(members):
        raise ZipError('central directory count differs from local members')
    base = None
    for entry, member in zip(entries, members):
        if entry['local'] != 0xffffffff:
            relation = member['header_offset'] - entry['local']
            base = relation if base is None else base
            if relation != base:
                raise ZipError('central directory offsets inconsistent with local members')
        if entry['crc'] != int(member['crc32'], 16):
            raise ZipError('central directory CRC differs from local member')
    if base is not None and base != start - (members[0]['header_offset'] - start) - (start - start) and base > start:
        raise ZipError('archive begins before the scanned start')
    return end


def _archive_extension(names):
    names = [n for n in names if n]
    lowered = {n.casefold() for n in names}
    if '[content_types].xml' in lowered:
        for prefix, ext in (('word/', 'docx'), ('xl/', 'xlsx'), ('ppt/', 'pptx'), ('visio/', 'vsdx')):
            if any(n.startswith(prefix) for n in lowered):
                return ext
    if 'mimetype' in lowered:
        return 'odf.zip'
    if 'meta-inf/manifest.mf' in lowered:
        return 'jar'
    return 'zip'


def validate_zip(src, offset, limits, staging):
    """Walk a ZIP from a local header. Returns (rows, span_end_or_None)."""
    members, position, failure = [], offset, None
    while src[position:position + 4] == ZIP_LOCAL:
        if len(members) >= 65535 * 16 or position - offset > limits['max_file']:
            failure = 'archive exceeds file size or member limit'
            break
        try:
            info = _local_member(src, position, limits['max_file'])
        except (ZipError, ValueError, zlib.error, struct.error, OSError) as error:
            failure = f'member at {position}: {error}'
            members.append(dict(header_offset=position, failed=str(error)[:200]))
            break
        members.append(info)
        position = info['next_offset']
    good = [m for m in members if 'failed' not in m]
    if not good:
        error = members[0]['failed'] if members else 'not a local header'
        status = 'unsupported' if 'encrypted' in error or 'compression method' in error else 'rejected'
        return [dict(kind='zip', offset=offset, status=status, name=f'{offset}.zip', detail=dict(error=error))], None
    complete_end = None
    if failure is None:
        try:
            complete_end = _central_directory(src, offset, good, position, len(good) + 1)
            if complete_end - offset > limits['max_file']:
                failure, complete_end = 'archive exceeds file size limit', None
        except (ZipError, struct.error) as error:
            failure = f'central directory: {error}'
    names = [m.get('name') for m in good]
    if complete_end is not None:
        ext = _archive_extension(names)
        writer = StreamWriter(staging)
        try:
            _copy_range(src, offset, complete_end, writer)
            staged = writer.finish()
        except BaseException:
            writer.abort()
            raise
        return [dict(kind='zip', offset=offset, status='recovered', name=f'{offset}.{ext}',
                     relative_path=f'zip_archives/{shard(offset)}/{offset}.{ext}', staged=staged,
                     detail=dict(validation='every_member_size_crc32_and_central_directory', members=len(good),
                                 member_names=names[:200], archive_bytes=complete_end - offset))], complete_end
    # Stage 4: member salvage of independently verified members only.
    rows = [dict(kind='zip', offset=offset, status='rejected', name=f'{offset}.zip',
                 detail=dict(error=failure, verified_members=len(good), member_names=names[:200],
                             note='archive not verifiable as a whole; verified members salvaged separately'))]
    for member in good:
        if member['directory'] or member['size'] == 0 and not member.get('name'):
            continue
        name = member.get('name') or f"member_{member['header_offset']}"
        parts = [safe_component(p) for p in name.rstrip('/').split('/') if p]
        writer = StreamWriter(staging)
        try:
            again = _local_member(src, member['header_offset'], limits['max_file'], sink=writer)
            if again['crc32'] != member['crc32']:
                raise ZipError('member changed between reads')
            staged = writer.finish()
        except (ZipError, ValueError, zlib.error, struct.error) as error:
            writer.abort()
            rows.append(dict(kind='zip_member', offset=member['header_offset'], status='rejected', name=name,
                             detail=dict(error=str(error)[:200], archive_offset=offset)))
            continue
        except BaseException:
            writer.abort()
            raise
        rows.append(dict(kind='zip_member', offset=member['header_offset'], status='recovered', name=name,
                         relative_path=f'zip_members/{shard(offset)}/{offset}/' + '/'.join(parts or ['unnamed']),
                         staged=staged, detail=dict(validation='size_crc32_complete_stream', archive_offset=offset,
                                                    archive_path=name, crc32=member['crc32'],
                                                    path_reliability='archive member path (untrusted metadata)')))
    return rows, members[-1].get('next_offset') if 'failed' not in members[-1] else good[-1]['next_offset']


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class AutoRecovery:
    def __init__(self, source, output, options=None, *, progress_path=None, resume_from=None, cancel=None,
                 log=print):
        self.source = _no_symlinks(source)
        self.output = _no_symlinks(output)
        self.options = normalize_options(options)
        self.progress_path = Path(progress_path) if progress_path else None
        self.resume_from = Path(resume_from) if resume_from else None
        self.cancel = cancel or (lambda: False)
        self.log = log
        self.counts = Counter()
        self.stage, self.stage_index, self.status, self.message = 'diagnose', 1, 'running', ''
        self.scanned = 0
        self.planned = None
        self.started = time.monotonic()
        self.last_progress = 0
        self.speed_samples = deque(maxlen=20)
        self.src = None
        self.ctx = StageContext(self.progress_path, self.cancel, self.log)
        self.stage_count = None

    # --- progress -------------------------------------------------------
    def progress(self, force=False):
        """Mirror this engine's counters into the shared progress.json writer."""
        ctx = self.ctx
        ctx.stage, ctx.stage_index, ctx.stage_count = self.stage, self.stage_index, self.stage_count
        ctx.status, ctx.message = self.status, self.message
        final = self.stage in ('summary', 'done')
        if self.stage == 'raw_scan' or (final and getattr(self, 'route', None) == 'raw'):
            ctx.unit, ctx.done, ctx.total = 'bytes', self.scanned, self.planned
            ctx.counts.update(verified_files=self.counts['recovered'], candidates=self.counts['candidates'],
                              failed=self.counts['rejected'])
        elif final and getattr(self, 'route', None) == 'rebuild' and self.planned:
            ctx.unit, ctx.done, ctx.total = 'bytes', self.scanned, self.planned
        stats = self.src.stats if self.src else {}
        ctx.extra_read_bytes = stats.get('candidate_bytes', 0)
        ctx.progress(force)
        self.last_progress_value = ctx.snapshot()

    # --- setup ----------------------------------------------------------
    def _prepare(self):
        resuming = self.resume_from is not None
        in_place = self.output.exists()
        if in_place and (resuming or not (self.output / 'auto.sqlite').is_file()):
            raise ValueError('Output must be a new directory, or a previous automatic-recovery folder to continue in place')
        if self.output == self.source or self.source in self.output.parents:
            raise ValueError('Output must not be inside the source')
        if self.options['work_dir']:
            work = Path(self.options['work_dir'])
            if not work.is_dir():
                raise ValueError('The temporary work folder must be an existing directory')
        # Open the source before creating any state, so a sharing violation or read error leaves
        # no half-initialised state behind.
        self.src = BoundedSource(self.source)
        identity = dict(path=str(self.source.resolve()), stat=self.src.identity, evidence=self.src.evidence(),
                        identity_kind='stat_plus_sampled_regions_not_full_content_hash')
        if not in_place:
            self.output.mkdir(parents=True)
        self.state_path = self.output / 'auto.sqlite'
        resuming = resuming or in_place
        if resuming and not in_place:
            prior = self.resume_from
            if prior.is_dir():
                prior = prior / 'payload' / 'auto.sqlite' if (prior / 'payload' / 'auto.sqlite').is_file() else prior / 'auto.sqlite'
            _no_symlinks(prior)
            source_db = sqlite3.connect(prior.resolve().as_uri() + '?mode=ro', uri=True)
            target = sqlite3.connect(str(self.state_path))
            try:
                source_db.backup(target)
            finally:
                target.close()
                source_db.close()
        self.state = AutoState(self.state_path)
        self.staging = Staging(self.output)
        if in_place and self.state.get('identity') is None:
            resuming = False  # an earlier attempt stopped before recording anything: start fresh here
        if resuming:
            prior_identity, prior_options = self.state.get('identity'), self.state.get('options')
            if prior_identity is None or self.state.get('schema') != SCHEMA:
                raise ValueError('Resume source is not an automatic-recovery state')
            for key in ('size', 'mtime_ns'):
                if prior_identity['stat'][key] != identity['stat'][key]:
                    raise SourceChangedError(f'Source {key} differs from the prior run; refusing to resume')
            if prior_identity['evidence']['sha256'] != identity['evidence']['sha256']:
                raise SourceChangedError('Sampled source evidence differs from the prior run; refusing to resume')
            changed = [k for k in STRUCTURAL_OPTIONS if (prior_options or {}).get(k) != self.options.get(k)]
            if changed:
                raise ValueError(f'Options {changed} differ from the prior run; resume requires the same scan options')
            if self.state.get('status') == 'completed':
                raise ValueError('Prior run already completed; nothing to resume')
            self.run_id = (self.state.get('run') or 1) + 1
        else:
            self.run_id = 1
            self.state.put_many  # noqa: B018 (documented single-writer API)
            with self.state.transaction():
                self.state.put_many(dict(schema=SCHEMA, schema_version=SCHEMA_VERSION, identity=identity,
                                         options=self.options, checkpoint=None, created_at=time.time()))
        with self.state.transaction():
            self.state.put_many(dict(run=self.run_id, status='running', options_current=self.options,
                                     resumed_from=str(self.resume_from or self.output) if resuming else None))
        self.limits = dict(max_file=self.options['max_file_mib'] * MiB, max_total=self.options['max_total_mib'] * MiB,
                           max_decoded=self.options['max_decoded_mib'] * MiB)
        self.reserve = self.options['reserve_mib'] * MiB
        if free_space(self.output) < self.reserve:
            raise StopScan('output_space_low', 'Output disk free space is below the configured reserve')
        self._prepared = True

    # --- stage 1/2 ------------------------------------------------------
    def _diagnose(self):
        from diagnose_recovery_source import diagnose
        self.stage, self.stage_index = 'diagnose', 1
        self.progress(force=True)
        if self.run_id > 1 and self.state.get('diagnostic'):
            return self.state.get('diagnostic')
        report = diagnose(self.source)
        self.state.put('diagnostic', report)
        return report

    def _logical(self, diagnostic):
        self.stage, self.stage_index = 'logical_index', 2
        self.progress(force=True)
        from revivex_scan_session import scan_source
        session = self.output / 'logical' / 'session.sqlite'
        try:
            summary = scan_source(self.source, session, cancel=self.cancel)
        except Exception as error:  # A failed index is a known gap, not a crash.
            summary = dict(status='failed', error=f'{type(error).__name__}: {error}'[:500])
        self.state.put('logical', summary)
        self.counts['logical_candidates'] = int((summary.get('counts') or {}).get('candidates', 0) or 0)
        gaps = summary.get('status') != 'finished'
        return summary, gaps

    # --- stage 3 --------------------------------------------------------
    def _range(self):
        start = self.options['scan_start']
        end = len(self.src) if self.options['max_scan_bytes'] is None else min(len(self.src), start + self.options['max_scan_bytes'])
        if start >= len(self.src):
            raise ValueError('scan_start is beyond the end of the source')
        return start, end

    def _raw_scan(self, index=3):
        self.stage, self.stage_index = 'raw_scan', index
        start, end = self._range()
        checkpoint = self.state.get('checkpoint')
        position = start if checkpoint is None else max(start, min(end, checkpoint))
        self.planned = end - start
        self.scanned = position - start
        prior_counts = self.state.get('counts') or {}
        self.counts.update(prior_counts)
        self.total_output = self.state.db.execute('SELECT coalesce(sum(size),0) FROM contents').fetchone()[0]
        block = self.options['block_mib'] * MiB
        blocks = queue.Queue(maxsize=2)
        results = queue.Queue()
        stop_reader = threading.Event()
        zip_queue = queue.Queue(maxsize=4096)
        pending = deque()  # ordered blocks: dict(end, outstanding, rows, counts)
        by_id = {}
        pool = ThreadPoolExecutor(max_workers=self.options['workers'], thread_name_prefix='revivex-validate')
        self.pending_contents = {}
        stop = None

        def reader():
            try:
                cursor = position
                while cursor < end and not stop_reader.is_set():
                    length = min(block, end - cursor)
                    extra = min(OVERLAP, len(self.src) - cursor - length)
                    buffer = bytearray(length + extra)
                    got = self.src.readinto_at(cursor, buffer)
                    if got < length:
                        raise OSError(errno.EIO, f'Short read at offset {cursor}: expected {length}, got {got}')
                    blocks.put((cursor, length, bytes(buffer[:got])))
                    cursor += length
                blocks.put(None)
            except BaseException as error:
                blocks.put(error)

        def zip_lane():
            skip_until = self.state.get('zip_skip_until') or 0
            while True:
                item = zip_queue.get()
                if item is None:
                    return
                block_id, offset, window = item
                try:
                    if offset < skip_until:
                        results.put((block_id, [], Counter(zip_inside_previous_archive=1), None))
                        continue
                    rows, span_end = validate_zip(window, offset, self.limits, self.staging)
                    if span_end:
                        skip_until = max(skip_until, span_end)
                    results.put((block_id, rows, Counter(), dict(zip_skip_until=skip_until)))
                except BaseException as error:
                    results.put((block_id, [], Counter(), error))

        def submit(block_id, fn, *args):
            by_id[block_id]['outstanding'] += 1

            def run():
                try:
                    out = fn(*args)
                    rows, counts = out if isinstance(out, tuple) else (out, Counter())
                    results.put((block_id, rows, counts, None))
                except BaseException as error:
                    results.put((block_id, [], Counter(), error))
            pool.submit(run)

        def apply(item):
            nonlocal stop
            block_id, rows, counts, extra = item
            entry = by_id[block_id]
            entry['outstanding'] -= 1
            entry['counts'].update(counts)
            if isinstance(extra, BaseException):
                if isinstance(extra, OSError) and extra.errno in (errno.ENOSPC, getattr(errno, 'EDQUOT', -1)):
                    stop = stop or StopScan('output_space_low', f'Output write failed: {extra}')
                elif isinstance(extra, (SourceChangedError,)):
                    stop = stop or StopScan('source_changed', str(extra))
                elif isinstance(extra, OSError):
                    stop = stop or StopScan('source_read_error', f'{type(extra).__name__}: {extra}')
                else:
                    stop = stop or StopScan('failed', f'Validator error: {type(extra).__name__}: {extra}')
                return
            if isinstance(extra, dict):
                entry['meta'].update(extra)
            for row in rows:
                self._place(row, entry)
            entry['rows'].extend(rows)

        lane = threading.Thread(target=zip_lane, name='revivex-zip-lane', daemon=True)
        lane.start()
        read_thread = threading.Thread(target=reader, name='revivex-reader', daemon=True)
        read_thread.start()
        last_commit = last_check = time.monotonic()
        next_id = 0
        try:
            while True:
                if self.cancel():
                    stop = stop or StopScan('cancelled', 'Cancelled by user; committed results retained')
                if stop is None and len(pending) < 8:
                    try:
                        item = blocks.get(timeout=0.05)
                    except queue.Empty:
                        item = False
                    if item is None:
                        if not pending:
                            break
                    elif isinstance(item, BaseException):
                        stop = StopScan('source_read_error', f'{type(item).__name__}: {item}')
                    elif item is not False:
                        offset, length, data = item
                        block_id = next_id
                        next_id += 1
                        entry = dict(id=block_id, end=offset + length, outstanding=0, rows=[], counts=Counter(), meta={}, contents={})
                        pending.append(entry)
                        by_id[block_id] = entry
                        self._dispatch(block_id, offset, length, data, entry, submit, zip_queue)
                        if item is not None and blocks.empty() and not read_thread.is_alive() and not pending:
                            break
                # Drain results without blocking the scan.
                while True:
                    try:
                        apply(results.get(timeout=0 if (pending and pending[0]['outstanding'] == 0) else 0.01))
                    except queue.Empty:
                        break
                    if stop and stop.status in ('output_space_low',):
                        break
                now = time.monotonic()
                if now - last_check >= 5:
                    last_check = now
                    try:
                        self.src.check_unchanged()
                    except (SourceChangedError, OSError) as error:
                        stop = stop or StopScan('source_changed', str(error))
                    if free_space(self.output) < self.reserve:
                        stop = stop or StopScan('output_space_low', 'Output disk free space fell below the reserve')
                if self.total_output > self.limits['max_total'] and stop is None:
                    stop = StopScan('output_limit', 'Total output byte limit reached; remaining range not scanned')
                if now - last_commit >= 0.5 or stop is not None:
                    self._commit(pending, by_id, start)
                    last_commit = now
                self.progress()
                if stop is not None:
                    stop_reader.set()
                    # Let in-flight validators finish so their staged files are accounted for.
                    deadline = time.monotonic() + 120
                    while any(e['outstanding'] for e in pending) and time.monotonic() < deadline:
                        try:
                            apply(results.get(timeout=0.2))
                        except queue.Empty:
                            pass
                    self._commit(pending, by_id, start)
                    break
                if item is None and not pending:
                    break
                if item is None:
                    # Reader finished; wait for outstanding work.
                    try:
                        apply(results.get(timeout=0.05))
                    except queue.Empty:
                        pass
                    self._commit(pending, by_id, start)
                    if not pending:
                        break
        finally:
            stop_reader.set()
            zip_queue.put(None)
            pool.shutdown(wait=True)
            lane.join(timeout=30)
            while True:  # unblock a reader waiting on a full queue
                try:
                    blocks.get_nowait()
                except queue.Empty:
                    break
            read_thread.join(timeout=30)
        checkpoint = self.state.get('checkpoint') or start
        if stop is not None:
            with self.state.transaction():
                self.state.db.execute('INSERT INTO unscanned(start,end,run,reason) VALUES(?,?,?,?)',
                                      (checkpoint, end, self.run_id, stop.status))
            self.status, self.message = stop.status, stop.reason
        elif end < len(self.src) or start > 0:
            with self.state.transaction():
                if start > 0:
                    self.state.db.execute('INSERT INTO unscanned(start,end,run,reason) VALUES(?,?,?,?)', (0, start, self.run_id, 'before_scan_start'))
                if end < len(self.src):
                    self.state.db.execute('INSERT INTO unscanned(start,end,run,reason) VALUES(?,?,?,?)', (end, len(self.src), self.run_id, 'bounded_trial_range'))
            self.status, self.message = 'limited', 'Bounded range scanned; the rest of the source was not scanned'
        else:
            self.status = 'completed'

    def _dispatch(self, block_id, offset, length, data, entry, submit, zip_queue):
        window = WindowedSource(self.src, offset, data)
        limit = length
        ntfs = []
        for kind, signature in SIGNATURES:
            found = data.find(signature, 0, limit)
            while found >= 0:
                absolute = offset + found
                if kind == 'ntfs':
                    if absolute % 512 == 0:
                        ntfs.append(absolute)
                        entry['counts']['ntfs_aligned_candidates'] += 1
                else:
                    entry['counts'][kind + '_candidates'] += 1
                    if kind == 'zip':
                        entry['outstanding'] += 1
                        zip_queue.put((block_id, absolute, window))
                    elif kind == 'png':
                        submit(block_id, validate_png, window, absolute, self.limits, self.staging)
                    else:
                        submit(block_id, validate_sqlite, window, absolute, self.limits, self.staging)
                found = data.find(signature, found + 1, limit)
        if ntfs:
            for index in range(0, len(ntfs), 2048):
                submit(block_id, validate_ntfs_batch, window, ntfs[index:index + 2048], self.limits, self.staging)

    def _place(self, row, entry):
        staged = row.pop('staged', None)
        row.setdefault('sub', '')
        if staged is None:
            return
        path, digest, size = staged
        known = self.pending_contents.get(digest) or self.state.content_output(digest)
        if known:
            path.unlink()
            output, run = (known if isinstance(known, tuple) else (known, self.run_id))
            row.update(status='verified_duplicate', sha256=digest, size=size, output='',
                       detail=dict(row.get('detail', {}), duplicate_of=output, duplicate_of_run=run,
                                   intended_path=row.get('relative_path')))
            return
        relative = row['relative_path']
        target = self.output / 'files' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        suffix = 1
        while target.exists():  # never overwrite (e.g. an orphan from an interrupted run)
            suffix += 1
            stem = Path(relative)
            relative = str(stem.with_name(f'{stem.stem}__r{suffix}{stem.suffix}').as_posix())
            target = self.output / 'files' / relative
        os.replace(path, target)
        output = 'files/' + relative
        row.update(output=output, sha256=digest, size=size)
        self.pending_contents[digest] = (output, self.run_id)
        entry['contents'][digest] = (output, size)
        self.total_output += size

    def _commit(self, pending, by_id, start):
        done = []
        while pending and pending[0]['outstanding'] == 0:
            done.append(pending.popleft())
        if not done:
            return
        diagnostic_budget = self.options['max_diagnostic_rows'] - self.counts['diagnostic_rows']
        with self.state.transaction():
            for entry in done:
                for row in entry['rows']:
                    self.counts['candidates'] += 1
                    self.counts[row['status']] += 1
                    if row['status'] not in ('recovered', 'verified_duplicate'):
                        if diagnostic_budget <= 0:
                            self.counts['diagnostic_rows_not_stored'] += 1
                            continue
                        diagnostic_budget -= 1
                        self.counts['diagnostic_rows'] += 1
                    self.state.db.execute('''INSERT OR IGNORE INTO candidates(run,kind,offset,sub,status,name,relative_path,output,size,sha256,detail)
                                             VALUES(?,?,?,?,?,?,?,?,?,?,?)''',
                                          (self.run_id, row['kind'], row['offset'], row.get('sub', ''), row['status'], row.get('name', ''),
                                           row.get('relative_path', ''), row.get('output', ''), row.get('size', 0), row.get('sha256', ''),
                                           _json(row.get('detail', {}))))
                for digest, (output, size) in entry['contents'].items():
                    self.state.db.execute('INSERT OR IGNORE INTO contents(sha256,run,output,size) VALUES(?,?,?,?)', (digest, self.run_id, output, size))
                    self.pending_contents.pop(digest, None)
                self.counts.update(entry['counts'])
                by_id.pop(entry['id'], None)
            last = done[-1]
            meta = dict(checkpoint=last['end'], counts=dict(self.counts))
            for entry in done:
                meta.update(entry['meta'])
            self.state.put_many(meta)
        self.scanned = last['end'] - start

    # --- routing helpers ------------------------------------------------
    def _damaged(self, diagnostic):
        """Inferred ransomware ranges (hypothesis) plus user-supplied damaged ranges."""
        inferred = [list(r) for r in (diagnostic.get('inferred_damage_ranges') or [])]
        ranges = sorted(inferred + [list(r) for r in self.options['damaged_ranges']])
        return [r for r in ranges if r[1] > r[0]]

    def _sample_probe(self, damaged, index):
        from revivex_evidence import sample_probe
        prior = self.state.get('sample_probe')
        self.stage, self.stage_index = 'sample_probe', index
        self.ctx.begin('sample_probe', index, self.stage_count, unit='items')
        if prior:
            return prior
        result = sample_probe(self.src, damaged=damaged, samples=self.options['sample_count'], ctx=self.ctx)
        self.state.put('sample_probe', result)
        return result

    def _work_dir(self):
        stored = self.state.get('work_path')
        if stored:
            return Path(stored)
        if self.options['work_dir']:
            tag = hashlib.sha256(f'{self.output.resolve()}|{time.time()}'.encode()).hexdigest()[:10]
            path = Path(self.options['work_dir']) / f'revivex-work-{tag}'
        else:
            path = self.output / '_work'
        self.state.put('work_path', str(path))  # recorded first: a kill below cannot strand the run
        path.mkdir(parents=True, exist_ok=True)
        (path / 'README.txt').write_text(
            'ReViveX intermediate evidence for one recovery run (safe to delete after the run is finished).\n'
            f'Output folder: {self.output}\n', encoding='utf-8')
        return path

    def _rebuild(self, damaged):
        from revivex_rebuild import RebuildRecovery
        work = self._work_dir()
        options = dict(block_size_mib=self.options['block_size_mib'], reserve_bytes=self.reserve,
                       match_missing_blocks=self.options['match_missing_blocks'],
                       include_deleted=not self.options['skip_deleted'])
        engine = RebuildRecovery(self.src, self.output, work, damaged=damaged, options=options, ctx=self.ctx,
                                 first_index=3, stage_count=self.stage_count)
        result = engine.run()
        self.state.put('rebuild', result)
        totals = result.get('totals', {})
        self.counts['recovered'] = totals.get('extracted', 0)
        self.counts['usable'] = totals.get('by_grade', {}).get('usable', 0)
        self.counts['not_recovered'] = totals.get('not_extracted', 0)
        self.ctx.counts.update(verified_files=self.counts['usable'], candidates=totals.get('extracted', 0) + totals.get('not_extracted', 0),
                               failed=totals.get('not_extracted', 0))
        self.status = 'completed'
        self.message = 'Block map rebuilt and files recovered under original names; see auto_manifest.json, 清单.jsonl and 未恢复清单.jsonl'

    # --- run ------------------------------------------------------------
    def run(self):
        error = None
        try:
            self._prepare()
            diagnostic = self._diagnose()
            if diagnostic.get('logical_mapping') == 'invalidated_source_changed':
                raise StopScan('source_changed', 'Source changed during diagnosis')
            damaged = self._damaged(diagnostic)
            route = (self.state.get('route') or {}).get('route')
            if route is None:
                if self.options['route'] != 'auto':
                    route = self.options['route']
                elif diagnostic.get('logical_mapping') == 'validated_metadata_only':
                    route = 'logical'
                else:
                    self.stage_count = None
                    probe = self._sample_probe(damaged, 2)
                    route = 'rebuild' if probe['verdict'] == 'ntfs_metadata_found' else 'raw'
                self.state.put('route', dict(route=route, damaged_ranges=damaged, deep_raw=self.options['deep_raw']))
            self.route = route
            if route == 'logical':
                self.stage_count = 4 if self.options['deep_raw'] else 3
                logical, gaps = self._logical(diagnostic)
                self.state.put('route', dict(route=route, logical_gaps=gaps, deep_raw=self.options['deep_raw'],
                                             damaged_ranges=damaged))
                if gaps or self.options['deep_raw']:
                    self.stage_count, self.route = 4, 'raw'
                    self._raw_scan(3)
                else:
                    self.status = 'completed'
                    self.message = 'Logical index complete without known gaps; deep raw salvage not run (select it manually if needed)'
            elif route == 'rebuild':
                self.stage_count = 11
                if self.state.get('sample_probe') is None:
                    self._sample_probe(damaged, 2)
                self._rebuild(damaged)
            else:
                self.stage_count = 4
                if self.state.get('sample_probe') is None and self.options['route'] == 'auto':
                    self._sample_probe(damaged, 2)
                self._raw_scan(3)
        except Cancelled as stop:
            self.status, self.message = 'cancelled', str(stop)
        except (StopScan, StopRun) as stop:
            self.status, self.message = stop.status, stop.reason
        except SourceChangedError as exc:
            self.status, self.message = 'source_changed', str(exc)
        except Exception as exc:
            self.status, self.message, error = 'failed', f'{type(exc).__name__}: {exc}'[:1000], exc
        finally:
            self.stage = 'summary'
            self.stage_index = self.stage_count or self.stage_index + 1
            self.progress(force=True)
            manifest = self._finish()
            self.stage = 'done'
            self.progress(force=True)
        if error is not None:
            raise error
        return manifest

    def _finish(self):
        if not getattr(self, '_prepared', False):
            # Preparation refused this run (e.g. a completed or mismatched prior run): write nothing.
            for handle in (getattr(self, 'state', None), self.src):
                if handle is not None:
                    try:
                        handle.close()
                    except Exception:
                        pass
            return dict(status=self.status, error=self.message)
        unchanged = None
        if self.src is not None:
            try:
                unchanged = self.src.check_unchanged()
            except (SourceChangedError, OSError):
                unchanged = False
                self.status = 'source_changed'
        stats = dict(self.src.stats) if self.src else {}
        elapsed = time.monotonic() - self.started
        route = (self.state.get('route') or {}).get('route')
        rebuild = self.state.get('rebuild')
        if route == 'rebuild':
            evidence = ((rebuild or {}).get('evidence_scan') or {})
            self.scanned = evidence.get('scanned', stats.get('sequential_bytes', 0))
            self.planned = sum(b - a for a, b in evidence.get('ranges', [])) or None
        scanned = self.scanned
        manifest = dict(
            schema=SCHEMA, schema_version=SCHEMA_VERSION, status=self.status, message=self.message, run=self.run_id,
            route=self.state.get('route'), diagnostic_summary={k: (self.state.get('diagnostic') or {}).get(k) for k in ('logical_mapping', 'ransomware_marker', 'inferred_damage_ranges', 'physical_size')},
            options=self.options, source_identity=self.state.get('identity'), source_stat_unchanged=unchanged,
            scan=dict(planned_bytes=self.planned, scanned_bytes=scanned, checkpoint=self.state.get('checkpoint'),
                      unscanned=[dict(start=a, end=b, reason=r, run=run) for a, b, run, r in
                                 self.state.db.execute('SELECT start,end,run,reason FROM unscanned ORDER BY start')]),
            io=dict(sequential_read_bytes=stats.get('sequential_bytes', 0), candidate_read_bytes=stats.get('candidate_bytes', 0),
                    cache_hits=stats.get('cache_hits', 0), cache_misses=stats.get('cache_misses', 0),
                    io_amplification=round((stats.get('sequential_bytes', 0) + stats.get('candidate_bytes', 0)) / scanned, 4) if scanned else None,
                    wall_seconds=round(elapsed, 3), throughput_bytes_per_second=round(scanned / elapsed) if elapsed and scanned else None,
                    peak_memory_bytes=peak_memory_bytes()),
            counts=dict(self.counts), logical=self.state.get('logical'),
            sample_probe=self.state.get('sample_probe'), rebuild=rebuild, work_dir=self.state.get('work_path'),
            results=dict(listing='清单.jsonl', not_recovered='未恢复清单.jsonl', final_folder='最终结果',
                         categories=['可用', '待确认', '疑似损坏', '缩略图缓存']) if route == 'rebuild' else None,
            scan_complete=self.status == 'completed', original_content_completeness='unknown',
            warning=WARNING,
            limitations=REBUILD_LIMITATIONS if route == 'rebuild' else ['Fragmented or non-contiguous files (e.g. across VHDX payload blocks) are not reassembled.',
                         'Nonresident NTFS streams require a validated mapping and are not extracted raw.',
                         'Encrypted ZIP members and damaged DEFLATE bytes cannot be reconstructed.',
                         'Inferred Gentlemen intervals are scanned, never silently skipped; unscanned ranges are listed explicitly.',
                         'Source identity is stat plus sampled regions; no full-source content hash was computed.'])
        with self.state.transaction():
            self.state.put_many(dict(status=self.status, message=self.message))
        if route == 'rebuild':
            (self.output / '结果说明.txt').write_text(RESULT_README, encoding='utf-8')
            state_db = self.output / '_state' / 'extract.sqlite'
            if state_db.is_file():  # keep the listings current even after cancel / stop
                from revivex_named_extract import open_state
                from revivex_organize import write_manifests
                try:
                    extract_state = open_state(state_db)
                    try:
                        manifest['listings'] = write_manifests(extract_state, self.output)
                    finally:
                        extract_state.close()
                except (OSError, sqlite3.Error) as error:
                    manifest['listing_write_error'] = f'{type(error).__name__}: {error}'[:300]
        temporary = self.output / 'auto_manifest.json.tmp'
        try:
            temporary.write_text(json.dumps(manifest, ensure_ascii=True, indent=2), encoding='utf-8')
            from revivex_stage import replace_with_retry
            replace_with_retry(temporary, self.output / 'auto_manifest.json')  # a viewer may hold it (Windows)
        except OSError as error:
            manifest['manifest_write_error'] = f'{type(error).__name__}: {error}'[:300]
        try:
            self.staging.dir.rmdir()
        except OSError:
            pass
        if self.src is not None:
            self.src.close()
        self.state.close()
        return manifest


def iter_rows(state_path, run=None, limit_diagnostics=None):
    """Yield candidate rows (dicts) of one run for catalog ingestion."""
    db = sqlite3.connect(Path(state_path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if run is None:
            row = db.execute("SELECT value FROM meta WHERE key='run'").fetchone()
            run = json.loads(row[0]) if row else 1
        for values in db.execute('SELECT kind,offset,sub,status,name,relative_path,output,size,sha256,detail FROM candidates WHERE run=? ORDER BY offset, kind, sub', (run,)):
            kind, offset, sub, status, name, relative, output, size, digest, detail = values
            yield dict(kind=kind, offset=offset, sub=sub, status=status, name=name, relative_path=relative,
                       output=output, size=size, sha256=digest, detail=json.loads(detail))
    finally:
        db.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--progress', type=Path)
    parser.add_argument('--resume-from', type=Path, help='Prior auto workspace (or its auto.sqlite); same source and options required')
    parser.add_argument('--max-file-mib', type=int)
    parser.add_argument('--max-total-mib', type=int)
    parser.add_argument('--max-scan-bytes', type=int)
    parser.add_argument('--scan-start', type=int)
    parser.add_argument('--deep-raw', action='store_true')
    parser.add_argument('--workers', type=int)
    parser.add_argument('--block-mib', type=int)
    parser.add_argument('--reserve-mib', type=int)
    parser.add_argument('--work-dir', help='Existing fast folder (e.g. an SSD) for intermediate evidence; recovered files still go to OUTPUT')
    parser.add_argument('--damaged-range', action='append', default=[], metavar='START-END',
                        help='Known damaged/encrypted byte range of the source (repeatable); added to inferred ranges')
    parser.add_argument('--block-size-mib', type=int, help='Override the inferred VHDX block size (rebuild route)')
    parser.add_argument('--route', choices=ROUTES, help='Force a route instead of automatic routing (testing/expert use)')
    parser.add_argument('--cancel-file', type=Path, help='Stop at the next safe point once this file exists')
    parser.add_argument('--skip-deleted', action='store_true', help='Do not recover deleted files (rebuild route)')
    args = parser.parse_args(argv)
    options = {k: getattr(args, k) for k in ('max_file_mib', 'max_total_mib', 'max_scan_bytes', 'scan_start', 'workers', 'block_mib', 'reserve_mib', 'work_dir', 'block_size_mib', 'route') if getattr(args, k) is not None}
    if args.damaged_range:
        options['damaged_ranges'] = args.damaged_range
    if args.skip_deleted:
        options['skip_deleted'] = True
    if args.deep_raw:
        options['deep_raw'] = True
    cancel = (lambda: args.cancel_file.exists()) if args.cancel_file else None
    engine = AutoRecovery(args.source, args.output, options, progress_path=args.progress, resume_from=args.resume_from,
                          cancel=cancel)
    manifest = engine.run()
    print(json.dumps({k: v for k, v in manifest.items() if k not in ('source_identity',)}, ensure_ascii=True, indent=2))
    return 0 if manifest['status'] in ('completed', 'limited') else 2


if __name__ == '__main__':
    raise SystemExit(main())
