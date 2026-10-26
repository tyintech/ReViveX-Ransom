"""Sample probe, one-pass evidence scan and offline evidence index.

Field lessons built in (see docs/superpowers/specs/2026-10-25-field-recovery-summary.md):
- Every source read is bounded (no whole-source mmap/read_bytes, WinError 1450).
- A ~1-minute sample probe decides whether NTFS metadata survived before the
  long scan starts.
- The scan reads the source once, sequentially, and keeps only small evidence:
  FILE records, INDX blocks, file-start signatures, all-zero MiBs, NTFS boot
  sectors and VHDX metadata tables. It checkpoints every 30 s; on resume the
  evidence files are truncated back to the last durable checkpoint, so an
  interruption never duplicates entries. Checkpoint replacement retries while
  Windows readers hold the file.
- Inferred ransomware ranges are scanned last, never silently skipped.
- The index stage reads only the evidence directory, never the source.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import queue
import re
import sqlite3
import struct
import threading
import time

from revivex_ntfs_evidence import (INDEX_BLOCK, MAGICS, RECORD_SIZE, classify, fixup_ok, parse_boot, parse_indx,
                                   parse_record, parse_vhdx_metadata, TYPE_CODE)
from revivex_stage import Cancelled, StopRun, read_json, write_json_atomic
from revivex_source_io import SourceChangedError, free_space

MiB = 1024 * 1024
META_CAPTURE = 128 * 1024
MAGIC_ALIGN = 512
EVIDENCE_FILES = {'records.bin': 8 + RECORD_SIZE, 'indx.bin': 8 + INDEX_BLOCK, 'magic.bin': 9,
                  'zero.bin': 8, 'boot.bin': 8 + 512, 'meta.bin': 8 + META_CAPTURE}
# Magics starting with 0x00 (MP4 'ftyp' boxes) are found via 'ftyp' instead, so zero-filled
# sectors cost nothing in the per-sector signature pass.
_FIRST = re.compile(b'[' + b''.join(re.escape(bytes([m[0]])) for m in set(MAGICS) if m[0]) + b']')
_ZERO_MIB = bytes(MiB)


def merge_ranges(ranges):
    merged = []
    for start, end in sorted((max(0, a), b) for a, b in ranges if b > a):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [tuple(r) for r in merged]


def overlaps(ranges, start, end):
    return any(a < end and start < b for a, b in ranges)


def plan_ranges(size, damaged, align=MiB):
    """Plaintext-likely ranges first, inferred-damaged ranges last (all scanned)."""
    damaged = merge_ranges((a - a % align, min(size, -(-b // align) * align)) for a, b in damaged if a < size)
    plain, previous = [], 0
    for start, end in damaged:
        if start > previous:
            plain.append((previous, start))
        previous = max(previous, end)
    if previous < size:
        plain.append((previous, size))
    return [list(r) for r in plain + list(damaged)]


# ---------------------------------------------------------------------------
# Stage: sample probe
# ---------------------------------------------------------------------------
def scan_buffer(data, base, out=None):
    """Find evidence in one buffer. Returns counts; appends packed entries to ``out``."""
    counts = Counter()
    view = memoryview(data)
    position = data.find(b'FILE')
    while position >= 0:
        if position % 512 == 0 and fixup_ok(data, position, RECORD_SIZE):  # 512: old MBR partitions at sector 63
            counts['file'] += 1
            if out is not None:
                out['records.bin'].append(struct.pack('<Q', base + position) + bytes(view[position:position + RECORD_SIZE]))
        position = data.find(b'FILE', position + 1)
    position = data.find(b'INDX')
    while position >= 0:
        if position % 512 == 0 and fixup_ok(data, position, INDEX_BLOCK):
            counts['indx'] += 1
            if out is not None:
                out['indx.bin'].append(struct.pack('<Q', base + position) + bytes(view[position:position + INDEX_BLOCK]))
        position = data.find(b'INDX', position + 1)
    position = data.find(b'NTFS    ')
    while position >= 0:
        start = position - 3
        if start >= 0 and start % 512 == 0 and parse_boot(bytes(view[start:start + 512])):
            counts['boot'] += 1
            if out is not None:
                out['boot.bin'].append(struct.pack('<Q', base + start) + bytes(view[start:start + 512]))
        position = data.find(b'NTFS    ', position + 1)
    position = data.find(b'metadata')
    while position >= 0:
        if (base + position) % 65536 == 0:
            counts['vhdx_metadata'] += 1
            if out is not None:
                out.setdefault('meta_offsets', []).append(base + position)
        position = data.find(b'metadata', position + 1)
    firsts = bytes(view[0::MAGIC_ALIGN])
    for match in _FIRST.finditer(firsts):
        offset = match.start() * MAGIC_ALIGN
        kind = classify(view[offset:offset + 16])
        if kind:
            counts['magic'] += 1
            if out is not None:
                out['magic.bin'].append(struct.pack('<QB', base + offset, TYPE_CODE[kind]))
    position = data.find(b'ftyp', 4)
    while position >= 0:
        offset = position - 4
        if offset % MAGIC_ALIGN == 0 and classify(view[offset:offset + 16]) == 'mp4':
            counts['magic'] += 1
            if out is not None:
                out['magic.bin'].append(struct.pack('<QB', base + offset, TYPE_CODE['mp4']))
        position = data.find(b'ftyp', position + 1)
    for offset in range(0, len(data) - len(data) % MiB, MiB):
        if view[offset:offset + MiB] == _ZERO_MIB:
            counts['zero_mib'] += 1
            if out is not None:
                out['zero.bin'].append(struct.pack('<Q', base + offset))
    return counts


def sample_probe(source, *, damaged=(), samples=256, sample_bytes=MiB, ctx=None):
    """Read evenly spaced samples (bounded) and count surviving NTFS metadata."""
    size = len(source)
    sample_bytes = min(sample_bytes, size)
    if size <= samples * sample_bytes:
        offsets = list(range(0, size, sample_bytes))
    else:
        step = (size - sample_bytes) // max(1, samples - 1)
        offsets = [i * step - (i * step) % 4096 for i in range(samples)]
    plain = [o for o in offsets if not overlaps(damaged, o, o + sample_bytes)]
    counts, read = Counter(), 0
    for i, offset in enumerate(plain or offsets):
        if ctx:
            ctx.check_cancel()
        data = source.read_at(offset, sample_bytes, kind='candidate')
        read += len(data)
        counts.update(scan_buffer(data, offset))
        if ctx:
            ctx.advance(i + 1, total=len(plain or offsets), candidates=counts['file'] + counts['indx'])
    verdict = 'ntfs_metadata_found' if counts['file'] >= 4 or counts['indx'] >= 1 else 'no_ntfs_metadata_found'
    return dict(verdict=verdict, samples=len(plain or offsets), sample_bytes=sample_bytes, read_bytes=read,
                samples_outside_inferred_damage=len(plain), counts=dict(counts))


# ---------------------------------------------------------------------------
# Stage: evidence scan
# ---------------------------------------------------------------------------
def read_tolerant(source, position, length, smallest=4096):
    """Read [position, position+length); retry failing parts in smaller pieces.

    Returns (buffer, unread) where unread lists (start, end) ranges that could
    not be read even at ``smallest`` granularity. Those bytes are filled with
    0xFF (not zero, so they are never reported as all-zero evidence).
    """
    buffer = bytearray(length)
    try:
        if source.readinto_at(position, buffer) == length:
            return buffer, []
    except OSError:
        pass
    unread = []

    def fill(offset, size, piece):
        view = memoryview(buffer)[offset:offset + size]
        try:
            if source.readinto_at(position + offset, view) == size:
                return
        except OSError:
            pass
        if size <= smallest:
            view[:] = b'\xff' * size
            if unread and unread[-1][1] == position + offset:
                unread[-1][1] = position + offset + size
            else:
                unread.append([position + offset, position + offset + size])
            return
        step = max(smallest, piece)
        for sub in range(0, size, step):
            fill(offset + sub, min(step, size - sub), max(smallest, step // 256))

    for offset in range(0, length, MiB):
        fill(offset, min(MiB, length - offset), 64 * 1024)
    return buffer, unread

class EvidenceScan:
    def __init__(self, source, directory, *, damaged=(), block=8 * MiB, checkpoint_seconds=30.0,
                 reserve_bytes=1024 * MiB, ctx=None, limit_bytes=None):
        self.source, self.dir, self.ctx = source, Path(directory), ctx
        self.block, self.checkpoint_seconds = block, checkpoint_seconds
        self.reserve, self.limit = reserve_bytes, limit_bytes
        self.ranges = plan_ranges(len(source), damaged)
        self.checkpoint_path = self.dir / 'checkpoint.json'

    def _load(self):
        identity = dict(size=self.source.identity['size'], mtime_ns=self.source.identity['mtime_ns'])
        checkpoint = read_json(self.checkpoint_path)
        if checkpoint is not None:
            if checkpoint.get('source') != identity:
                raise SourceChangedError('Evidence checkpoint belongs to a different or changed source; refusing to resume')
            if checkpoint.get('ranges') != self.ranges:
                raise ValueError('Evidence checkpoint uses a different scan plan (damaged ranges changed); use a new work folder')
            return checkpoint
        return dict(schema='revivex.evidence-scan', schema_version=1, source=identity, ranges=self.ranges,
                    range_index=0, offset=self.ranges[0][0] if self.ranges else 0,
                    sizes={name: 0 for name in EVIDENCE_FILES}, counts={}, scanned=0, elapsed=0.0,
                    status='running', block=self.block, unread=[])

    def run(self):
        self.dir.mkdir(parents=True, exist_ok=True)
        cp = self._load()
        if cp.get('status') == 'finished':
            return cp
        files = {}
        for name in EVIDENCE_FILES:
            handle = open(self.dir / name, 'ab+')
            handle.truncate(cp['sizes'].get(name, 0))  # drop entries after the last durable checkpoint
            handle.seek(0, 2)
            files[name] = handle
        counts = Counter(cp['counts'])
        planned = sum(b - a for a, b in self.ranges)
        stop = threading.Event()
        work = queue.Queue(maxsize=3)

        def reader():
            try:
                for index in range(cp['range_index'], len(self.ranges)):
                    start, end = self.ranges[index]
                    position = cp['offset'] if index == cp['range_index'] else start
                    while position < end and not stop.is_set():
                        length = min(self.block, end - position)
                        buffer, unread = read_tolerant(self.source, position, length)
                        work.put(('data', index, position, buffer, unread))
                        position += length
                    if stop.is_set():
                        return
                    work.put(('range_done', index, end))
                work.put(('done',))
            except BaseException as error:  # surfaced on the consumer side
                work.put(('error', error))

        thread = threading.Thread(target=reader, name='revivex-evidence-reader', daemon=True)
        session_scanned, session_started = 0, time.monotonic()

        def checkpoint(range_index, offset, status='running'):
            nonlocal session_scanned, session_started
            for handle in files.values():
                handle.flush()
                os.fsync(handle.fileno())
            cp.update(range_index=range_index, offset=offset, sizes={n: f.tell() for n, f in files.items()},
                      counts=dict(counts), scanned=cp['scanned'] + session_scanned,
                      elapsed=cp['elapsed'] + time.monotonic() - session_started, status=status, updated=time.time())
            session_scanned, session_started = 0, time.monotonic()
            write_json_atomic(self.checkpoint_path, cp)

        last = time.monotonic()
        resume_index, resume_offset = cp['range_index'], cp['offset']
        thread.start()
        try:
            while True:
                item = work.get()
                kind = item[0]
                if kind == 'data':
                    _, index, position, buffer, unread = item
                    if unread:
                        cp.setdefault('unread', []).extend(unread)  # reported; never silently counted as scanned
                    found = {name: [] for name in EVIDENCE_FILES}
                    counts.update(scan_buffer(buffer, position, found))
                    for meta_offset in found.get('meta_offsets', ()):
                        raw = self.source.read_at(meta_offset, META_CAPTURE, kind='candidate')
                        if parse_vhdx_metadata(raw):
                            found['meta.bin'].append(struct.pack('<Q', meta_offset) + raw.ljust(META_CAPTURE, b'\0'))
                    for name in EVIDENCE_FILES:
                        if found[name]:
                            files[name].write(b''.join(found[name]))
                    session_scanned += len(buffer)
                    resume_index, resume_offset = index, position + len(buffer)
                    if self.ctx:
                        self.ctx.extra_read_bytes = self.source.stats.get('candidate_bytes', 0)
                        self.ctx.advance(cp['scanned'] + session_scanned, total=planned,
                                         candidates=counts['file'] + counts['indx'])
                    if time.monotonic() - last >= self.checkpoint_seconds:
                        self.source.check_unchanged()
                        if free_space(self.dir) < self.reserve:
                            checkpoint(resume_index, resume_offset)
                            raise StopRun('work_space_low', 'Work folder free space fell below the reserve; evidence kept for resume')
                        checkpoint(resume_index, resume_offset)
                        last = time.monotonic()
                    if self.ctx and self.ctx.cancel():
                        checkpoint(resume_index, resume_offset)
                        raise Cancelled('Evidence scan cancelled; checkpoint saved')
                    if self.limit is not None and cp['scanned'] + session_scanned >= self.limit:
                        checkpoint(resume_index, resume_offset, status='limited')
                        return cp
                elif kind == 'range_done':
                    _, index, end = item
                    nxt = index + 1
                    resume_index, resume_offset = nxt, self.ranges[nxt][0] if nxt < len(self.ranges) else end
                    checkpoint(resume_index, resume_offset)
                    last = time.monotonic()
                elif kind == 'done':
                    checkpoint(len(self.ranges), len(self.source), status='finished')
                    return cp
                else:
                    raise item[1]  # read error: no checkpoint; resume truncates to the last durable sizes
        finally:
            stop.set()
            while thread.is_alive():
                try:
                    work.get_nowait()
                except queue.Empty:
                    thread.join(0.05)
            for handle in files.values():
                handle.close()


# ---------------------------------------------------------------------------
# Stage: evidence index (evidence directory only; never the source)
# ---------------------------------------------------------------------------
INDEX_SCHEMA = '''
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS records(phys INTEGER PRIMARY KEY, ev INTEGER NOT NULL, number INTEGER, seq INTEGER,
  lsn INTEGER, base INTEGER, base_seq INTEGER, flags INTEGER, names TEXT, attrs TEXT, has_list INTEGER, volume_name TEXT);
CREATE TABLE IF NOT EXISTS indx(phys INTEGER PRIMARY KEY, vcn INTEGER, parent INTEGER, parent_seq INTEGER, entries INTEGER);
CREATE TABLE IF NOT EXISTS entries(child INTEGER, child_seq INTEGER, parent INTEGER, parent_seq INTEGER, ns INTEGER,
  name TEXT, indx_phys INTEGER);
CREATE TABLE IF NOT EXISTS boot(phys INTEGER PRIMARY KEY, cluster_size INTEGER, sector_size INTEGER,
  total_sectors INTEGER, mft_lcn INTEGER, mirror_lcn INTEGER, serial INTEGER);
CREATE TABLE IF NOT EXISTS vhdx_meta(phys INTEGER PRIMARY KEY, block_size INTEGER, virtual_size INTEGER, logical_sector_size INTEGER);
'''


def open_index(path, readonly=False):
    if readonly:
        db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, check_same_thread=False)
    else:
        db = sqlite3.connect(str(path), check_same_thread=False)
        db.executescript(INDEX_SCHEMA)
    return db


def _meta_get(db, key, default=None):
    row = db.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
    return json.loads(row[0]) if row else default


def _meta_put(db, key, value):
    db.execute('INSERT INTO meta VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, json.dumps(value)))


def build_index(evidence_dir, index_path, *, ctx=None, batch=20000):
    """Parse captured evidence into SQLite. Resumable: each batch commits with its offset."""
    evidence_dir = Path(evidence_dir)
    cp = read_json(evidence_dir / 'checkpoint.json')
    if not cp or cp.get('status') not in ('finished', 'limited'):
        raise ValueError('Evidence scan has not finished; index requires a finished scan')
    db = open_index(index_path)
    if _meta_get(db, 'status') == 'finished' and _meta_get(db, 'evidence_sizes') == cp['sizes']:
        return summary(db)
    _meta_put(db, 'evidence_sizes', cp['sizes'])
    db.commit()
    sizes = cp['sizes']
    total = sum(sizes[name] for name in ('records.bin', 'indx.bin', 'boot.bin', 'meta.bin'))
    done_before = sum(_meta_get(db, 'done:' + name, 0) for name in ('records.bin', 'indx.bin', 'boot.bin', 'meta.bin'))
    progress = [done_before]

    def stream(name, handler):
        entry = EVIDENCE_FILES[name]
        limit = sizes[name] - sizes[name] % entry
        position = _meta_get(db, 'done:' + name, 0)
        with open(evidence_dir / name, 'rb') as handle:
            handle.seek(position)
            while position < limit:
                if ctx:
                    ctx.check_cancel()
                count = min(batch, (limit - position) // entry)
                chunk = handle.read(count * entry)
                rows = handler(chunk, position, entry)
                with db:
                    rows()
                    _meta_put(db, 'done:' + name, position + len(chunk))
                position += len(chunk)
                progress[0] += len(chunk)
                if ctx:
                    ctx.advance(progress[0], total=total)

    def records(chunk, start, entry):
        rows, bad = [], 0
        for i in range(0, len(chunk), entry):
            phys = struct.unpack_from('<Q', chunk, i)[0]
            record = parse_record(chunk[i + 8:i + entry])
            if record is None:
                bad += 1
                continue
            rows.append((phys, start + i + 8, record['number'], record['seq'], record['lsn'], record['base'],
                         record['base_seq'], record['flags'], json.dumps(record['names'], ensure_ascii=False),
                         json.dumps(record['attrs']), int(record['has_list']), record.get('volume_name')))

        def apply():
            db.executemany('INSERT OR IGNORE INTO records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', rows)
            _meta_put(db, 'bad_records', _meta_get(db, 'bad_records', 0) + bad)
        return apply

    def indx(chunk, start, entry):
        blocks, entries = [], []
        for i in range(0, len(chunk), entry):
            phys = struct.unpack_from('<Q', chunk, i)[0]
            parsed = parse_indx(chunk[i + 8:i + entry])
            if parsed is None:
                continue
            vcn, items = parsed
            parents = Counter((parent, parent_seq) for _, _, parent, parent_seq, _, _ in items)
            parent, parent_seq = parents.most_common(1)[0][0] if parents else (None, None)
            blocks.append((phys, vcn, parent, parent_seq, len(items)))
            entries.extend((c, cs, p, ps, ns, name, phys) for c, cs, p, ps, ns, name in items)

        def apply():
            db.executemany('INSERT OR IGNORE INTO indx VALUES(?,?,?,?,?)', blocks)
            db.executemany('INSERT INTO entries VALUES(?,?,?,?,?,?,?)', entries)
        return apply

    def boots(chunk, start, entry):
        rows = []
        for i in range(0, len(chunk), entry):
            phys = struct.unpack_from('<Q', chunk, i)[0]
            boot = parse_boot(chunk[i + 8:i + entry])
            if boot:
                rows.append((phys, boot['cluster_size'], boot['sector_size'], boot['total_sectors'], boot['mft_lcn'],
                             boot['mirror_lcn'], boot['serial']))
        return lambda: db.executemany('INSERT OR IGNORE INTO boot VALUES(?,?,?,?,?,?,?)', rows)

    def metas(chunk, start, entry):
        rows = []
        for i in range(0, len(chunk), entry):
            phys = struct.unpack_from('<Q', chunk, i)[0]
            found = parse_vhdx_metadata(chunk[i + 8:i + entry])
            if found:
                rows.append((phys, found.get('block_size'), found.get('virtual_size'), found.get('logical_sector_size')))
        return lambda: db.executemany('INSERT OR IGNORE INTO vhdx_meta VALUES(?,?,?,?)', rows)

    stream('records.bin', records)
    stream('indx.bin', indx)
    stream('boot.bin', boots)
    stream('meta.bin', metas)
    with db:
        db.execute('CREATE INDEX IF NOT EXISTS records_number ON records(number)')
        db.execute('CREATE INDEX IF NOT EXISTS entries_child ON entries(child, child_seq)')
        db.execute('CREATE INDEX IF NOT EXISTS entries_indx ON entries(indx_phys)')
        _meta_put(db, 'status', 'finished')
    result = summary(db)
    db.close()
    return result


def summary(db):
    one = lambda sql: db.execute(sql).fetchone()[0]
    return dict(records=one('SELECT count(*) FROM records'), bad_records=_meta_get(db, 'bad_records', 0),
                indx=one('SELECT count(*) FROM indx'), entries=one('SELECT count(*) FROM entries'),
                boot_sectors=one('SELECT count(*) FROM boot'), vhdx_metadata=one('SELECT count(*) FROM vhdx_meta'))


class MagicIndex:
    """File-start signatures from magic.bin as sorted arrays (9 bytes/entry, bisect lookups)."""

    def __init__(self, evidence_dir):
        from array import array
        cp = read_json(Path(evidence_dir) / 'checkpoint.json') or {}
        limit = cp.get('sizes', {}).get('magic.bin', 0)
        limit -= limit % 9
        runs, positions, kinds = [], array('Q'), bytearray()
        previous = -1
        with open(Path(evidence_dir) / 'magic.bin', 'rb') as handle:
            remaining = limit
            while remaining:
                chunk = handle.read(min(remaining, 9 * 65536))
                remaining -= len(chunk)
                for phys, code in struct.iter_unpack('<QB', chunk):
                    if phys < previous:
                        runs.append((positions, kinds))
                        positions, kinds = array('Q'), bytearray()
                    positions.append(phys)
                    kinds.append(code)
                    previous = phys
        runs.append((positions, kinds))
        # Each scan range is ascending; ranges are few, so lookups bisect each run.
        self.runs = [r for r in runs if len(r[0])]
        from revivex_ntfs_evidence import TYPES
        self.names = (None,) + TYPES
        self.count = sum(len(p) for p, _ in self.runs)

    def get(self, phys):
        import bisect
        for positions, kinds in self.runs:
            i = bisect.bisect_left(positions, phys)
            if i < len(positions) and positions[i] == phys:
                return self.names[kinds[i]]
        return None

    def __iter__(self):
        for positions, kinds in self.runs:
            for phys, code in zip(positions, kinds):
                yield phys, self.names[code]


class ZeroIndex:
    """All-zero MiB offsets as ascending arrays (8 bytes each), membership by bisect."""

    def __init__(self, evidence_dir):
        from array import array
        cp = read_json(Path(evidence_dir) / 'checkpoint.json') or {}
        limit = cp.get('sizes', {}).get('zero.bin', 0)
        limit -= limit % 8
        self.runs, current, previous = [], array('Q'), -1
        with open(Path(evidence_dir) / 'zero.bin', 'rb') as handle:
            remaining = limit
            while remaining:
                chunk = handle.read(min(remaining, 8 * 65536))
                remaining -= len(chunk)
                for (value,) in struct.iter_unpack('<Q', chunk):
                    if value < previous:
                        self.runs.append(current)
                        current = array('Q')
                    current.append(value)
                    previous = value
        if len(current):
            self.runs.append(current)

    def __contains__(self, offset):
        import bisect
        for run in self.runs:
            i = bisect.bisect_left(run, offset)
            if i < len(run) and run[i] == offset:
                return True
        return False

    def __len__(self):
        return sum(len(r) for r in self.runs)


def zero_mibs(evidence_dir):
    return ZeroIndex(evidence_dir)
