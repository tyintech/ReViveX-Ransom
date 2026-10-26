"""Locate missing guest blocks by file-structure probes, conservatively.

For files blocked only by a few unmapped or untrusted blocks, probes whose
bytes lie inside one missing block are derived from the parts that ARE
mapped: ZIP members (local header + CRC-32 from the central directory), PNG
chunk chains (CRC-32 per chunk), PDF xref objects ("N G obj" at the offset),
plus the file-start signatures of files that begin in the block.

Field lessons enforced:
- weak checks (a JPEG header and end marker) never confirm a location;
- a candidate is accepted only when EVERY probe passes and it is the ONLY
  candidate that does; ties are rejected, never broken by guesswork;
- before acceptance the same rules run on already-verified blocks (holdout).
  If any wrong slot passes there, matching is disabled for this run;
- candidate slots are read once, in ascending physical order, so a slow disk
  sees one sequential pass instead of random reads. The pass is resumable.
"""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
import json
from pathlib import Path
import random
import re
import sqlite3
import struct
import zlib

from revivex_block_map import TRUSTED, RANK, SlotIndex
from revivex_ntfs_evidence import MiB, expected_type, extension, primary_name

ZIP_FAMILY = {'zip', 'docx', 'xlsx', 'pptx', 'jar', 'apk', 'odt', 'ods', 'odp', 'vsdx', 'xps', 'epub', 'kmz', 'cdr'}
PDF_FAMILY = {'pdf', 'ai'}
PNG_FAMILY = {'png'}
DEFAULTS = dict(window=16, max_missing=2, min_strong=3, min_headers=3, holdout=200, min_holdout=20,
                max_candidates=256, max_read_bytes=256 * 1024 ** 3, seed=11)
SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS result(volume INTEGER, block INTEGER, slot INTEGER, strong_good INTEGER, strong_bad INTEGER,
  header_good INTEGER, header_bad INTEGER, PRIMARY KEY(volume, block, slot));
CREATE TABLE IF NOT EXISTS pass_state(slot INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS unreadable(slot INTEGER PRIMARY KEY);
'''


class FileReader:
    """Read file byte ranges through a volume map's TRUSTED blocks only."""

    def __init__(self, source, vmap, runs, size):
        self.source, self.vmap, self.size = source, vmap, size
        self.extents = []  # (file_offset, length, volume_offset or None for sparse)
        position = 0
        for lcn, count in runs:
            length = count * vmap.cluster_size
            self.extents.append((position, length, None if lcn is None else lcn * vmap.cluster_size))
            position += length

    def volume_offset(self, offset):
        for start, length, volume in self.extents:
            if start <= offset < start + length:
                return None if volume is None else volume + offset - start
        return None

    def block_of(self, offset):
        volume = self.volume_offset(offset)
        return None if volume is None else self.vmap.locate(volume)

    def read(self, offset, length):
        if offset < 0 or offset + length > self.size:
            return None
        parts = []
        while length > 0:
            located = None
            for start, ext_length, volume in self.extents:
                if start <= offset < start + ext_length:
                    located = (start, ext_length, volume)
                    break
            if located is None:
                return None
            start, ext_length, volume = located
            take = min(length, start + ext_length - offset)
            if volume is None:
                parts.append(bytes(take))
            else:
                v = volume + offset - start
                block, within = self.vmap.locate(v)
                take = min(take, self.vmap.block_size - within)
                entry = self.vmap.blocks.get(block)
                if entry is None or entry[1] not in TRUSTED:
                    return None
                data = self.source[entry[0] + within:entry[0] + within + take]
                if len(data) != take:
                    return None
                parts.append(data)
            offset += take
            length -= take
        return b''.join(parts)


# --- probe generation ---------------------------------------------------------
def zip_probes(reader, pending):
    tail_length = min(reader.size, 65557)
    tail = reader.read(reader.size - tail_length, tail_length)
    if tail is None:
        return []
    eocd = tail.rfind(b'PK\x05\x06')
    if eocd < 0 or eocd + 22 > len(tail):
        return []
    count, cd_size, cd_offset = struct.unpack_from('<HII', tail, eocd + 10)
    if cd_offset == 0xFFFFFFFF or cd_offset + cd_size > reader.size or cd_size > 64 * MiB:
        return []
    central = reader.read(cd_offset, cd_size)
    if central is None:
        return []
    probes, position = [], 0
    for _ in range(count):
        if central[position:position + 4] != b'PK\x01\x02':
            break
        method, _, _, crc, csize, usize, nlen, elen, clen = struct.unpack_from('<HHHIIIHHH', central, position + 10)
        lho = struct.unpack_from('<I', central, position + 42)[0]
        name = central[position + 46:position + 46 + nlen]
        position += 46 + nlen + elen + clen
        if 0xFFFFFFFF in (csize, usize, lho) or method not in (0, 8):
            continue
        located = reader.block_of(lho)
        end = reader.block_of(min(reader.size - 1, lho + 30 + nlen + csize + 1024))
        if located and end and located[0] == end[0] and located[0] in pending:
            probes.append((located[0], ('zip', located[1], name, method, csize, crc, usize)))
    return probes


def png_probes(reader, pending):
    if reader.read(0, 8) != b'\x89PNG\r\n\x1a\n':
        return []
    position = 8
    for _ in range(1_000_000):
        if position + 12 > reader.size:
            return []
        located = reader.block_of(position)
        if located is None:
            return []
        if located[0] in pending:
            return [(located[0], ('png', located[1]))]
        header = reader.read(position, 8)
        if header is None:
            return []
        length, kind = struct.unpack('>I4s', header)
        if length > 0x7FFFFFFF or not kind.isalpha():
            return []
        if kind == b'IEND':
            return []
        chunk = reader.read(position + 8, length + 4)
        if chunk is None:
            # The chunk body crosses into a pending block: probe from its start.
            for offset in (position + 8, position + 8 + length):
                where = reader.block_of(min(offset, reader.size - 1))
                if where and where[0] in pending:
                    return [(where[0], ('png_body', where[1], position, length, kind))]
            return []
        if zlib.crc32(chunk[:length], zlib.crc32(kind)) != struct.unpack('>I', chunk[length:])[0]:
            return []  # the known part is already damaged: no trustworthy chain
        position += 12 + length
    return []


_XREF = re.compile(rb'(\d{10}) (\d{5}) ([nf])')


def pdf_probes(reader, pending):
    tail = reader.read(max(0, reader.size - 1024), min(1024, reader.size))
    if tail is None:
        return []
    found = tail.rfind(b'startxref')
    match = re.match(rb'startxref\s+(\d+)', tail[found:]) if found >= 0 else None
    if not match:
        return []
    xref = int(match[1])
    head = reader.read(xref, min(64 * 1024, reader.size - xref)) if xref < reader.size else None
    if not head or not head.startswith(b'xref'):
        return []  # xref streams are not probed
    probes, cursor = [], 4
    for section in re.finditer(rb'\s(\d+) (\d+)\s', head[cursor:cursor + 64]):
        first, count = int(section[1]), int(section[2])
        body = head[cursor + section.end():]
        for i, entry in enumerate(_XREF.finditer(body)):
            if i >= count:
                break
            offset, gen, state = int(entry[1]), int(entry[2]), entry[3]
            if state == b'n' and 0 < offset < reader.size:
                located = reader.block_of(offset)
                if located and located[0] in pending:
                    probes.append((located[0], ('pdf', located[1], first + i, gen)))
        break
    return probes


# --- probe evaluation -----------------------------------------------------------
def evaluate(probe, data, base):
    """data: bytes of the candidate slot from offset ``base``. Returns (good, bad)."""
    kind = probe[0]
    if kind == 'zip':
        _, offset, name, method, csize, crc, *rest = probe
        usize = rest[0] if rest else None
        local = offset - base
        head = data[local:local + 30]
        if len(head) < 30 or head[:4] != b'PK\x03\x04':
            return 0, 1
        nlen, elen = struct.unpack_from('<HH', head, 26)
        if data[local + 30:local + 30 + nlen] != name:
            return 0, 1
        start = local + 30 + nlen + elen
        body = data[start:start + csize]
        if len(body) != csize:
            return 0, 0  # spills past the block: undecidable here
        try:
            if method == 0:
                content = body
            else:
                limit = (usize if usize is not None else 64 * MiB) + 1
                content = zlib.decompressobj(-15).decompress(body, limit)  # bounded: no zip bomb
                if usize is not None and len(content) != usize:
                    return 0, 1
        except zlib.error:
            return 0, 1
        return (1, 0) if zlib.crc32(content) == crc else (0, 1)
    if kind == 'png':
        return _png_walk(data, probe[1] - base)
    if kind == 'png_body':
        return 0, 0  # a chunk spanning blocks cannot be checked from one slot
    if kind == 'pdf':
        _, offset, number, gen = probe
        window = data[offset - base:offset - base + 40]
        return (1, 0) if re.match(rb'\s*%d\s+%d\s+obj' % (number, gen), window) else (0, 1)
    return 0, 0


def _png_walk(data, local):
    good = 0
    while local + 8 <= len(data):
        length, kind = struct.unpack_from('>I4s', data, local)
        if length > 0x7FFFFFFF or not kind.isalpha():
            return good, 1
        end = local + 12 + length
        if end > len(data):
            return good, 0  # continues in the next block
        if zlib.crc32(data[local + 8:end - 4], zlib.crc32(kind)) != struct.unpack_from('>I', data, end - 4)[0]:
            return good, 1
        good += 1
        if kind == b'IEND':
            return good, 0
        local = end
    return good, 0


def probe_span(probe, block_size):
    kind = probe[0]
    if kind == 'zip':
        return probe[1], min(block_size, probe[1] + 30 + len(probe[2]) + 65535 + probe[4])
    if kind == 'png':
        return probe[1], block_size
    if kind == 'pdf':
        return probe[1], min(block_size, probe[1] + 40)
    return None


# --- matcher -------------------------------------------------------------------------
class BlockMatcher:
    def __init__(self, source, models, magic, *, zeros=(), damaged=(), state_path, options=None, ctx=None):
        self.source, self.models, self.magic = source, models, magic
        self.zeros, self.damaged = zeros, list(damaged)
        self.options = dict(DEFAULTS, **(options or {}))
        self.ctx = ctx
        self.state = sqlite3.connect(str(state_path))
        self.state.executescript(SCHEMA)
        self.report = Counter()

    def tick(self, done=None, total=None, **counts):
        if self.ctx:
            self.ctx.check_cancel()
            self.ctx.advance(done, total=total, **counts)

    def _meta(self, key, default=None):
        row = self.state.execute('SELECT value FROM meta WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _put(self, key, value):
        with self.state:
            self.state.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', (key, json.dumps(value)))

    # --- planning -----------------------------------------------------------
    def plan(self):
        """{(volume, block): {'probes': [...], 'headers': [...], 'holdout': true_slot or None}}"""
        plan = {}
        rng = random.Random(self.options['seed'])
        for vid, model in self.models.items():
            vmap = model.vmap
            pending = {b for b, e in vmap.blocks.items() if e[1] not in TRUSTED} | set(vmap.unresolved)
            trusted = {b for b, e in vmap.blocks.items() if e[1] in TRUSTED}
            holdout = set(rng.sample(sorted(trusted), min(len(trusted), self.options['holdout'] * 3)))
            headers = defaultdict(list)
            for number, record in model.file_records():
                name = primary_name(record.names)
                if not name:
                    continue
                data = model.data(record)
                runs = data.get('runs')
                if not runs:
                    continue
                kind = expected_type(name[0])
                if kind and runs[0][0]:
                    block, within = vmap.locate(runs[0][0] * vmap.cluster_size)
                    if block in pending or block in holdout:
                        headers[block].append((within, kind))
                ext = extension(name[0])
                if ext not in ZIP_FAMILY | PDF_FAMILY | PNG_FAMILY:
                    continue
                touched = set()
                for lcn, count in runs:
                    if lcn is not None:
                        first, _ = vmap.locate(lcn * vmap.cluster_size)
                        last, _ = vmap.locate((lcn + count) * vmap.cluster_size - 1)
                        touched.update(range(first, last + 1))
                missing = touched & pending
                targets = missing if 0 < len(missing) <= self.options['max_missing'] else set()
                if not missing:
                    targets = touched & holdout  # verified blocks feed the holdout test
                if not targets:
                    continue
                reader = FileReader(self.source, _TrustExcept(vmap, targets), runs, data['size'])
                maker = zip_probes if ext in ZIP_FAMILY else pdf_probes if ext in PDF_FAMILY else png_probes
                try:
                    found = maker(reader, targets)
                except (struct.error, ValueError, IndexError, zlib.error):
                    found = []
                for block, probe in found:
                    plan.setdefault((vid, block), dict(probes=[], headers=[]))['probes'].append(probe)
            for block, items in headers.items():
                plan.setdefault((vid, block), dict(probes=[], headers=[]))['headers'] = items
            for (pvid, block), entry in plan.items():
                if pvid == vid:
                    entry['holdout'] = vmap.blocks[block][0] if block in trusted else None
        # Keep a bounded holdout of blocks that carry enough evidence to be judged.
        held = [k for k, e in plan.items() if e['holdout'] is not None and self._decidable(e)]
        keep = set(rng.sample(held, min(len(held), self.options['holdout'])))
        return {k: e for k, e in plan.items() if (e['holdout'] is None and self._decidable(e)) or k in keep}

    def _decidable(self, entry):
        return len(entry['probes']) >= 1 or len(entry['headers']) >= self.options['min_headers']

    def candidates(self, plan):
        self._index_headers(plan)
        owned = SlotIndex([m.vmap for m in self.models.values()], trusted_only=True)
        cands = {}
        size = len(self.source)
        per_volume = {}
        for vid, model in self.models.items():  # once per volume, not once per planned block
            vmap = model.vmap
            trusted = sorted(b for b, e in vmap.blocks.items() if e[1] in TRUSTED)
            grid = Counter(vmap.blocks[b][0] % vmap.block_size for b in trusted)
            residue, hits = grid.most_common(1)[0] if grid else (0, 0)
            per_volume[vid] = (trusted, residue, bool(trusted) and hits >= 0.9 * len(trusted))
        for key, entry in plan.items():
            vid, block = key
            vmap = self.models[vid].vmap
            B = vmap.block_size
            trusted, residue, on_grid = per_volume[vid]
            step = B if on_grid else MiB
            centres = set()
            left, right = bisect.bisect_left(trusted, block) - 1, bisect.bisect_right(trusted, block)
            for i in (left, right):
                if 0 <= i < len(trusted) and trusted[i] != block:
                    neighbour = trusted[i]
                    centres.add(vmap.blocks[neighbour][0] + (block - neighbour) * B)
            slots = set()
            window = self.options['window']
            for centre in centres:
                base = centre - centre % step + (residue % step if on_grid else 0)
                for d in range(-window, window + 1):
                    slots.add(base + d * step)
            vote = Counter()
            for offset, kind in entry['headers'][:12]:
                for start in self._header_starts(offset, kind):
                    vote[start] += 1
            slots.update(s for s, v in vote.most_common(self.options['max_candidates']) if v >= 2)
            true_slot = entry['holdout']
            valid = []
            for start in sorted(slots):
                if start < 0 or start + B > size or start % MiB:
                    continue
                if start != true_slot and owned.overlaps(start, start + B):
                    continue
                if any(a < start + B and start < b for a, b in self.damaged):
                    continue
                if all(start + m * MiB in self.zeros for m in range(B // MiB)):
                    continue
                valid.append(start)
            # Keep the most plausible candidates when over the cap: header votes, then nearness.
            near = lambda s: min((abs(s - c) for c in centres), default=1 << 62)
            valid.sort(key=lambda s: (-vote.get(s, 0), near(s), s))
            cands[key] = sorted(valid[:self.options['max_candidates']])
        return cands

    def _header_starts(self, offset, kind):
        return [p - offset for p in self._by_key.get((offset % MiB, kind), ()) if p >= offset]

    def _index_headers(self, plan):
        wanted = {(o % MiB, t) for e in plan.values() for o, t in e['headers'][:12]}
        self._by_key = defaultdict(list)
        if wanted:
            for phys, found in self.magic:
                key = (phys % MiB, found)
                if key in wanted and len(self._by_key[key]) < 5000:
                    self._by_key[key].append(phys)

    # --- read pass ------------------------------------------------------------
    def read_pass(self, plan, cands):
        by_slot = defaultdict(list)
        for key, slots in cands.items():
            for slot in slots:
                by_slot[slot].append(key)
        done = {s for (s,) in self.state.execute('SELECT slot FROM pass_state')}
        order = sorted(by_slot)
        read_bytes = self._meta('read_bytes', 0)  # the budget spans resumes
        for n, slot in enumerate(order):
            if slot in done:
                continue
            spans = []
            for key in by_slot[slot]:
                B = self.models[key[0]].vmap.block_size
                for probe in plan[key]['probes']:
                    span = probe_span(probe, B)
                    if span:
                        spans.append(span)
            data, base = b'', 0
            if spans:
                base, end = min(s for s, _ in spans), max(e for _, e in spans)
                if read_bytes + end - base > self.options['max_read_bytes']:
                    self.report['read_budget_exhausted'] += 1
                    break
                try:
                    data = self.source.read_at(slot + base, end - base, kind='candidate')
                except OSError:
                    data = None
                if data is None or len(data) != end - base:
                    with self.state:  # unreadable: blocks listing this slot stay undecided
                        self.state.execute('INSERT OR IGNORE INTO unreadable VALUES(?)', (slot,))
                        self.state.execute('INSERT OR IGNORE INTO pass_state VALUES(?)', (slot,))
                    continue
                read_bytes += len(data)
            rows = []
            for key in by_slot[slot]:
                entry = plan[key]
                strong_good = strong_bad = header_good = header_bad = 0
                for probe in entry['probes']:
                    good, bad = evaluate(probe, data, base)
                    strong_good += good
                    strong_bad += bad
                for offset, kind in entry['headers']:
                    if self.magic.get(slot + offset) == kind:
                        header_good += 1
                    else:
                        header_bad += 1
                rows.append((key[0], key[1], slot, strong_good, strong_bad, header_good, header_bad))
            with self.state:
                self.state.executemany('INSERT OR REPLACE INTO result VALUES(?,?,?,?,?,?,?)', rows)
                self.state.execute('INSERT OR IGNORE INTO pass_state VALUES(?)', (slot,))
                self.state.execute('INSERT OR REPLACE INTO meta VALUES(?,?)', ('read_bytes', json.dumps(read_bytes)))
            if self.ctx:
                self.ctx.extra_read_bytes = self.source.stats.get('candidate_bytes', 0)
            self.tick(n + 1, len(order))
        return read_bytes

    # --- decisions ----------------------------------------------------------------
    def passes(self, strong_good, strong_bad, header_good, header_bad, n_headers):
        if strong_bad or header_bad:
            return False
        if strong_good >= self.options['min_strong']:
            return True
        return strong_good == 0 and n_headers >= self.options['min_headers'] and header_good == n_headers

    def decide(self, plan, cands):
        read = {slot for (slot,) in self.state.execute('SELECT slot FROM pass_state')}
        read -= {slot for (slot,) in self.state.execute('SELECT slot FROM unreadable')}
        results = defaultdict(list)
        for vid, block, slot, sg, sb, hg, hb in self.state.execute('SELECT * FROM result'):
            if (vid, block) in plan and self.passes(sg, sb, hg, hb, len(plan[(vid, block)]['headers'])):
                results[(vid, block)].append((slot, sg, hg))
        holdout_samples = holdout_false = holdout_correct = 0
        accepted = []
        for key, entry in plan.items():
            passing = results.get(key, [])
            if any(slot not in read for slot in cands.get(key, ())):
                self.report['undecided_unread_candidates'] += 1
                continue  # uniqueness cannot be judged before every candidate was read
            if entry['holdout'] is not None:
                holdout_samples += 1
                wrong = [p for p in passing if p[0] != entry['holdout']]
                holdout_false += bool(wrong)
                holdout_correct += len(passing) == 1 and passing[0][0] == entry['holdout']
                continue
            if len(passing) == 1:
                slot, sg, hg = passing[0]
                accepted.append((sg * 10 + hg, key, slot, 'structure_verified' if sg else 'header_verified', sg + hg))
            elif len(passing) > 1:
                self.report['ambiguous_rejected'] += 1
            else:
                self.report['no_candidate_passed'] += 1
        enabled = not (holdout_false and holdout_samples)
        if holdout_samples < self.options['min_holdout']:
            self.report['holdout_below_minimum'] = 1
        holdout = dict(samples=holdout_samples, correct=holdout_correct, wrong_slot_passed=holdout_false,
                       matcher_enabled=enabled)
        return accepted if enabled else [], holdout

    def run(self):
        if self._meta('status') == 'applied':
            return self._meta('summary', {})
        plan = self.plan()
        self.tick(0, 1, candidates=len(plan))
        cands = self.candidates(plan)
        read_bytes = self.read_pass(plan, cands)
        accepted, holdout = self.decide(plan, cands)
        accepted.sort(key=lambda a: a[0], reverse=True)
        taken = set()
        for vmap in (m.vmap for m in self.models.values()):
            taken |= {e[0] for e in vmap.blocks.values() if e[1] in TRUSTED}
        applied = []
        for score, (vid, block), slot, method, checks in accepted:
            if slot in taken:
                self.report['slot_conflict_dropped'] += 1
                continue
            taken.add(slot)
            applied.append((vid, block, slot, method, checks))
        summary = dict(planned_blocks=sum(1 for e in plan.values() if e['holdout'] is None),
                       holdout=holdout, accepted=len(applied), candidate_read_bytes=read_bytes,
                       by_method=dict(Counter(a[3] for a in applied)), notes=dict(self.report),
                       rules=dict((k, self.options[k]) for k in ('window', 'max_missing', 'min_strong', 'min_headers')))
        self._put('accepted', applied)
        self._put('summary', summary)
        return summary

    def apply(self, map_path):
        """Write accepted mappings into map.sqlite (idempotent)."""
        applied = self._meta('accepted', [])
        db = sqlite3.connect(str(map_path))
        with db:
            for vid, block, slot, method, checks in applied:
                needed = db.execute('SELECT needed FROM blocks WHERE volume=? AND block=?', (vid, block)).fetchone()
                db.execute('INSERT OR REPLACE INTO blocks VALUES(?,?,?,?,?,?,?)',
                           (vid, block, slot, method, checks, checks, needed[0] if needed else 0))
                # An untrusted guess for another block on this slot is withdrawn.
                for other_vid, other_block, other_needed in db.execute(
                        'SELECT volume, block, needed FROM blocks WHERE start=? AND NOT (volume=? AND block=?)', (slot, vid, block)).fetchall():
                    db.execute("UPDATE blocks SET start=NULL, method='unresolved' WHERE volume=? AND block=?", (other_vid, other_block))
                    other = self.models.get(other_vid)
                    if other and other_block in other.vmap.blocks:
                        other.vmap.unresolved[other_block] = other.vmap.blocks.pop(other_block)[4]
                model = self.models.get(vid)
                if model:
                    model.vmap.unresolved.pop(block, None)
                    model.vmap.blocks[block] = [slot, method, checks, checks, needed[0] if needed else 0]
        db.close()
        self._put('status', 'applied')
        return len(applied)


class _TrustExcept:
    """A view of a volume map that treats ``hidden`` blocks as unreadable."""

    def __init__(self, vmap, hidden):
        self._vmap, self._hidden = vmap, set(hidden)
        self.cluster_size, self.block_size = vmap.cluster_size, vmap.block_size
        self.blocks = {b: e for b, e in vmap.blocks.items() if b not in self._hidden}

    def locate(self, offset):
        return self._vmap.locate(offset)
