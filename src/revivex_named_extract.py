"""Write files under their original names and folders through the rebuilt map.

Rules from the field:
- only files whose every block mapping is trusted are written; files touching
  unmapped, untrusted or inferred-encrypted ranges are listed, not written;
- resident (in-MFT) files come straight from the captured evidence and are
  written first, then user data before system folders, in physical order;
- strict parent/sequence paths are fixed before anything is written, so no
  later path-correction moves are needed;
- outputs are created exclusively (never replacing a file); a crash between
  placing a file and recording it is reconciled by content hash on resume;
- the source is read through bounded reads only;
- small files are not fsynced one by one (hours on a slow disk for millions of
  files). A process kill cannot lose written data; after an OS crash or power
  loss, files recorded shortly before the stop are re-hashed and any damaged
  one is moved aside (never deleted) to _中断损坏输出 and written again.
"""
from __future__ import annotations

import json
import errno
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from revivex_block_map import TRUSTED
from revivex_grading import grade
from revivex_ntfs_evidence import RECORD_SIZE, primary_name, resident_data
from revivex_stage import Cancelled, StopRun, place_exclusive
from revivex_source_io import free_space
from revivex_volume_model import is_system_path

MiB = 1024 * 1024
STAGING = '_提取暂存'
DELETED = '_已删除'  # staging namespace for deleted files: never collides with live ones
PARTS = '_parts'
QUARANTINE = '_中断损坏输出'
FSYNC_BYTES = 8 * MiB
RECHECK_SECONDS = 300
SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS files(volume INTEGER, number INTEGER, label TEXT, status TEXT, reason TEXT, path TEXT,
  path_known INTEGER, staged TEXT, final TEXT, size INTEGER, sha256 TEXT, grade TEXT, detail TEXT, methods TEXT,
  origin TEXT, written_at REAL, deleted INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(volume, number));
CREATE TABLE IF NOT EXISTS claimed(key TEXT PRIMARY KEY, volume INTEGER, number INTEGER);
CREATE TABLE IF NOT EXISTS moves(id INTEGER PRIMARY KEY, volume INTEGER, number INTEGER, src TEXT, dst TEXT,
  done INTEGER NOT NULL DEFAULT 0, undone INTEGER NOT NULL DEFAULT 0);
'''


def open_state(path):
    db = sqlite3.connect(str(path), timeout=60, check_same_thread=False)
    db.executescript(SCHEMA)
    return db


def long_path(path):
    path = os.path.abspath(str(path))
    if os.name == 'nt' and not path.startswith('\\\\?\\'):
        return '\\\\?\\' + path
    return path


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for piece in iter(lambda: handle.read(8 * MiB), b''):
            digest.update(piece)
    return digest.hexdigest()


class NamedExtractor:
    def __init__(self, source, models, evidence_dir, root, state, *, damaged=(), ctx=None, reserve_bytes=1024 * MiB,
                 memory_grade_limit=32 * MiB, include_deleted=True):
        self.source, self.models, self.root, self.state = source, models, Path(root), state
        self.records_path = Path(evidence_dir) / 'records.bin'
        self.damaged, self.ctx, self.reserve = list(damaged), ctx, reserve_bytes
        self.memory_grade_limit = memory_grade_limit
        self.include_deleted = include_deleted
        self._deleted = False
        self.staging = self.root / STAGING
        self.parts = self.root / PARTS
        self.rechecked = self._recheck_after_unclean_stop()
        self.claimed = {key: (v, n) for key, v, n in state.execute('SELECT key, volume, number FROM claimed')}
        self.done = {(v, n) for v, n in state.execute("SELECT volume, number FROM files WHERE status='extracted'")}
        self._dirs = set()

    def _meta(self, key, default=None):
        row = self.state.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _put(self, key, value):
        self.state.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', (key, json.dumps(value)))

    def _recheck_after_unclean_stop(self):
        """Re-hash files committed just before a stop that was not clean (crash/power loss)."""
        session = self._meta('session')
        if not session or session.get('clean'):
            return 0
        since = (session.get('last_commit_at') or 0) - RECHECK_SECONDS
        moved = 0
        rows = self.state.execute("SELECT volume, number, staged, final, size, sha256 FROM files WHERE status='extracted' "
                                  "AND written_at >= ?", (since,)).fetchall()
        for vid, number, staged, final, size, digest in rows:
            path = self.root / final if final else self.staging / staged
            try:
                ok = os.path.getsize(long_path(path)) == size and sha256_file(long_path(path)) == digest
            except OSError:
                ok = False
            if ok:
                continue
            if os.path.lexists(long_path(path)):
                aside = self.root / QUARANTINE / (final or f'{STAGING}/{staged}')
                os.makedirs(long_path(aside.parent), exist_ok=True)
                place_exclusive(long_path(path), long_path(aside))
            with self.state:
                self.state.execute("UPDATE files SET status='not_extracted', reason='interrupted_write_rechecked', staged=NULL "
                                   "WHERE volume=? AND number=?", (vid, number))
                self.state.execute('DELETE FROM claimed WHERE volume=? AND number=?', (vid, number))
            moved += 1
        return moved

    # --- planning -------------------------------------------------------
    def plan(self):
        tasks = []
        for vid, model in self.models.items():
            parts_by_record = {}
            records = list(model.file_records())
            if self.include_deleted:
                records += [(n, r, True) for n, r in model.deleted_records()]
            records = [item if len(item) == 3 else (*item, False) for item in records]
            for number, record, deleted in records:
                parts = model.strict_path(number, record.seq)
                if not parts or not primary_name(record.names):
                    parts = [('UNKNOWN', number), f'record_{number}']
                parts_by_record[number] = parts
                model.note_children(parts)
            for number, record, deleted in records:
                parts = parts_by_record[number]
                path, known = model.display_path(parts)
                data = dict(model.data(record), deleted=deleted)
                if deleted:
                    # Deleted files come after every live file; their clusters must still be free.
                    if 'error' not in data and not data.get('resident') and model.clusters_reused(data['runs']):
                        data = dict(error='deleted_clusters_reused_by_existing_file', size=data.get('size', 0), deleted=True)
                    kind = 'resident' if data.get('resident') else 'error' if 'error' in data else 'runs'
                    tasks.append(((5, 0, data.get('size', 0) or 0, number), vid, number, record, parts, path, known, kind, data))
                    continue
                if data.get('resident'):
                    tasks.append(((0, 0, 0, number), vid, number, record, parts, path, known, 'resident', data))
                    continue
                if 'error' in data:
                    tasks.append(((3, 0, 0, number), vid, number, record, parts, path, known, 'error', data))
                    continue
                first = next((lcn for lcn, _ in data['runs'] if lcn is not None), None)
                phys = model.vmap.phys(first * model.vmap.cluster_size) if first is not None else 0
                order = (1 + is_system_path(path), phys if phys is not None else 1 << 62, data['size'], number)
                tasks.append((order, vid, number, record, parts, path, known, 'runs', data))
        tasks.sort(key=lambda t: t[0])
        return tasks

    # --- output placement ------------------------------------------------
    def _ensure_dir(self, components):
        current, fixed = self.staging, []
        for part in components:
            candidate = current / part
            if candidate not in self._dirs:
                while os.path.lexists(long_path(candidate)) and not os.path.isdir(long_path(candidate)):
                    part += '__dir'
                    candidate = current / part
                os.makedirs(long_path(candidate), exist_ok=True)
                self._dirs.add(candidate)
            current = candidate
            fixed.append(part)
        return current, fixed

    def _target(self, vid, number, label, output_parts):
        prefix = [DELETED, label] if self._deleted else [label]
        folder, fixed = self._ensure_dir(prefix + output_parts[:-1])
        name = output_parts[-1]
        relative = '/'.join(fixed + [name])
        owner = self.claimed.get(relative.casefold())
        if (owner is not None and owner != (vid, number)) or (owner is None and os.path.isdir(long_path(folder / name))):
            stem, dot, suffix = name.rpartition('.')
            name = f'{stem}.__r{number}.{suffix}' if dot and stem else f'{name}.__r{number}'
            relative = '/'.join(fixed + [name])
        key = relative.casefold()
        if key not in self.claimed:
            self.claimed[key] = (vid, number)
            # Committed with the file row; a crash in between is reconciled by content hash.
            self.state.execute('INSERT OR REPLACE INTO claimed VALUES(?,?,?)', (key, vid, number))
        return folder / name, relative

    # --- extraction ------------------------------------------------------
    def _resident_bytes(self, record):
        with open(self.records_path, 'rb') as handle:
            handle.seek(record.ev)
            raw = handle.read(RECORD_SIZE)
        data = resident_data(raw)
        if data is None:
            raise ValueError('resident $DATA not found in captured record')
        return data

    def _pieces(self, model, data):
        pieces, methods, block = model.vmap.pieces(data['runs'], data['size'])
        if pieces is None:
            return None, methods, block
        for phys, length in pieces:
            if phys is not None and any(a < phys + length and phys < b for a, b in self.damaged):
                return None, 'inferred_encrypted_range', None
        return pieces, methods, None

    def _write(self, temp, pieces, size, initialized, keep):
        digest, written, buffer = hashlib.sha256(), 0, [] if keep else None
        with open(temp, 'wb') as handle:
            for phys, length in pieces:
                position = 0
                while position < length:
                    take = min(8 * MiB, length - position)
                    if phys is None or written >= initialized:
                        piece = bytes(take)
                    else:
                        piece = self.source.read_at(phys + position, take, kind='candidate')
                        if len(piece) != take:
                            raise OSError(errno.EIO, f'short source read at {phys + position}')
                        if written + take > initialized:  # bytes past the initialized size read as zero
                            cut = initialized - written
                            piece = piece[:cut] + bytes(take - cut)
                    handle.write(piece)
                    digest.update(piece)
                    if buffer is not None:
                        buffer.append(piece)
                    written += take
                    position += take
            handle.flush()
            if written >= FSYNC_BYTES:
                os.fsync(handle.fileno())
        return digest.hexdigest(), written, (b''.join(buffer) if buffer is not None else None)

    def _record(self, row, commit=False):
        self.state.execute('INSERT OR REPLACE INTO files(volume, number, label, status, reason, path, path_known, staged, final, '
                           'size, sha256, grade, detail, methods, origin, written_at, deleted) VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?,?,?,?,?)',
                           (*row, time.time(), int(self._deleted)))
        if commit:
            self.state.commit()

    def run(self):
        self.staging.mkdir(parents=True, exist_ok=True)
        self.parts.mkdir(parents=True, exist_ok=True)
        tasks = self.plan()
        total = len(tasks)
        counts = dict(extracted=0, usable=0, not_extracted=0)
        for row in self.state.execute("SELECT status, grade, count(*) FROM files GROUP BY status, grade"):
            if row[0] == 'extracted':
                counts['extracted'] += row[2]
                counts['usable'] += row[2] if row[1] == 'usable' else 0
        last_commit = last_space = time.monotonic()
        self._put('session', dict(clean=False, started_at=time.time(), last_commit_at=time.time()))
        self.state.commit()
        clean = False
        try:
            for index, (order, vid, number, record, parts, path, known, kind, data) in enumerate(tasks):
                if (vid, number) in self.done:
                    continue
                self._deleted = bool(data.get('deleted'))
                if self.ctx and index % 64 == 0:
                    self.ctx.check_cancel()
                    self.ctx.extra_read_bytes = self.source.stats.get('candidate_bytes', 0)
                    self.ctx.advance(index, total=total, verified_files=counts['usable'], candidates=total,
                                     failed=counts['not_extracted'])
                model = self.models[vid]
                label = model.vmap.label or f'卷{vid}'
                size = data.get('size', 0) or 0
                if kind == 'error':
                    self._record((vid, number, label, 'not_extracted', data['error'], path, int(known), None, size, None, None, None, None, None))
                    counts['not_extracted'] += 1
                    continue
                if kind == 'runs':
                    pieces, methods, block = self._pieces(model, data)
                    if pieces is None:
                        reason = methods + (f':block_{block}' if block is not None else '')
                        self._record((vid, number, label, 'not_extracted', reason, path, int(known), None, size, None, None, None, None, None))
                        counts['not_extracted'] += 1
                        continue
                if time.monotonic() - last_space > 2:
                    last_space = time.monotonic()
                    if free_space(self.root) < self.reserve:
                        raise StopRun('output_space_low', 'Output disk free space fell below the reserve; finished files are kept')
                target, relative = self._target(vid, number, label, model.output_parts(parts, number))
                temp = self.parts / f'{vid}-{number}.part'
                try:
                    if kind == 'resident':
                        content = self._resident_bytes(record)
                        with open(temp, 'wb') as handle:
                            handle.write(content)
                        digest, written, buffer, methods, origin = hashlib.sha256(content).hexdigest(), len(content), content, ['resident'], 'resident_mft_record'
                    else:
                        keep = size <= self.memory_grade_limit
                        digest, written, buffer = self._write(temp, pieces, size, data.get('init', size), keep)
                        origin = 'rebuilt_block_map'
                    name = parts[-1] if isinstance(parts[-1], str) else f'record_{number}'
                    verdict = grade(name, data=buffer) if buffer is not None and not name.lower().endswith(('.db', '.sqlite', '.sqlite3')) else \
                        grade(name, path=temp) if written <= self.memory_grade_limit else (None, None)
                    base_relative = relative
                    for attempt in range(100):
                        try:
                            place_exclusive(temp, long_path(target))
                            break
                        except FileExistsError:
                            if sha256_file(long_path(target)) == digest:
                                os.unlink(temp)  # our own placement from an interrupted run
                                break
                            # Someone else's bytes: never replace them, use the next free variant name.
                            tag = f'__r{number}' + 'bcdefghijklmnopqrstuvwxyz'[attempt % 25] + (str(attempt // 25) if attempt >= 25 else '')
                            stem, dot, suffix = base_relative.rpartition('.')
                            relative = f'{stem}.{tag}.{suffix}' if dot and '/' not in suffix else f'{base_relative}.{tag}'
                            target = self.staging / relative
                    else:
                        raise OSError(errno.EEXIST, 'no free output name')
                    self._record((vid, number, label, 'extracted', None, path, int(known), relative, written, digest,
                                  verdict[0], verdict[1], ','.join(methods), origin))
                    counts['extracted'] += 1
                    counts['usable'] += verdict[0] == 'usable'
                except OSError as error:
                    if error.errno in (errno.ENOSPC, getattr(errno, 'EDQUOT', -1)):
                        raise StopRun('output_space_low', 'Output disk is full; finished files are kept') from error
                    self._record((vid, number, label, 'not_extracted', f'error:{type(error).__name__}:{error}'[:300], path,
                                  int(known), None, size, None, None, None, None, None))
                    counts['not_extracted'] += 1
                except ValueError as error:
                    self._record((vid, number, label, 'not_extracted', f'error:{error}'[:300], path, int(known), None,
                                  size, None, None, None, None, None))
                    counts['not_extracted'] += 1
                if time.monotonic() - last_commit > 2:
                    self._put('session', dict(clean=False, last_commit_at=time.time()))
                    self.state.commit()
                    last_commit = time.monotonic()
            clean = True
        except (Cancelled, StopRun):
            clean = True  # an orderly stop: everything recorded is fully written by this process
            raise
        finally:
            self._put('session', dict(clean=clean, last_commit_at=time.time()))
            self.state.commit()
        if self.ctx:
            self.ctx.advance(total, total=total, verified_files=counts['usable'], candidates=total, failed=counts['not_extracted'])
        return dict(files=total, rechecked_after_unclean_stop=self.rechecked, **counts)


def grade_extracted(state, root, ctx=None, deep_limit=4 * 1024 ** 3):
    """Grade every extracted file that has no grade yet (large files from extraction)."""
    root = Path(root)
    rows = state.execute("SELECT volume, number, staged, final FROM files WHERE status='extracted' AND grade IS NULL").fetchall()
    try:
        for index, (vid, number, staged, final) in enumerate(rows):
            if ctx:
                ctx.check_cancel()
                ctx.advance(index, total=len(rows))
            path = root / final if final else root / STAGING / staged
            verdict = grade(Path(staged).name, path=long_path(path), deep_limit=deep_limit)
            state.execute('UPDATE files SET grade=?, detail=? WHERE volume=? AND number=?', (*verdict, vid, number))
            if index % 200 == 199:
                state.commit()
    finally:
        state.commit()
    counts = dict(state.execute("SELECT grade, count(*) FROM files WHERE status='extracted' GROUP BY grade").fetchall())
    if ctx:
        ctx.advance(len(rows), total=len(rows), verified_files=counts.get('usable', 0))
    return dict(graded_now=len(rows), by_grade=counts)
