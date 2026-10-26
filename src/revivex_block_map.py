"""Rebuild a lost VHDX block map (BAT) and decide volume membership from evidence.

Only the evidence index, captured signatures and all-zero MiBs are used; the
source is never read here. Nothing is hard-coded per site: cluster size,
block size, the physical slot grid and each volume's partition offset are
inferred and every inference is reported.

Model. VHDX payload blocks start at 1 MiB-aligned file offsets. For a volume
whose partition starts at guest offset P, a cluster at volume byte offset v
lives at guest offset g = P + v, in guest block g // B, at physical offset
start(g // B) + g % B. An INDX block whose directory record gives its LCN is
an exact anchor (phys, v). Hence phys - v is congruent to P modulo 1 MiB: the
residue identifies the volume ("family"), and each anchor pins one guest
MiB to one physical MiB. Block size and P mod B are then the hypothesis that
groups those MiBs consistently (no anchor contradicts it) and that the most
file headers confirm.

Field lessons enforced: a partition shift is refitted from header evidence,
not anchors alone; one physical slot holds one guest block; embedded disk
images' records (another LCN space) are excluded by a header-match ratio that
is bimodal in practice (100% vs 0-20%); interpolation is trusted only for the
neighbour distances where a leave-one-out test on verified blocks was exact.
"""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
import json
import math
import os
from pathlib import Path
import sqlite3
import time

from revivex_ntfs_evidence import (IMAGE_EXTENSIONS, MiB, RECORD_SIZE, expected_type, extension, primary_name)

CLUSTER_CANDIDATES = (4096, 512, 1024, 2048, 8192, 16384, 32768, 65536)
BLOCK_CANDIDATES_MIB = (1, 2, 4, 8, 16, 32, 64, 128, 256)
TRUSTED = frozenset({'anchor', 'interpolated_verified', 'searched_verified', 'interpolated_tested',
                     'structure_verified', 'header_verified'})
RANK = {'anchor': 4, 'structure_verified': 3, 'header_verified': 3, 'interpolated_verified': 2, 'searched_verified': 2,
        'interpolated_tested': 1, 'interpolated_bracketed': 1, 'interpolated_unverified': 0}
SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS volumes(id INTEGER PRIMARY KEY, label TEXT, status TEXT, cluster_size INTEGER,
  residue INTEGER, block_size INTEGER, shift INTEGER, anchors INTEGER, units INTEGER, details TEXT);
CREATE TABLE IF NOT EXISTS blocks(volume INTEGER, block INTEGER, start INTEGER, method TEXT, matched INTEGER,
  expected INTEGER, needed INTEGER, PRIMARY KEY(volume, block));
CREATE TABLE IF NOT EXISTS membership(phys INTEGER PRIMARY KEY, volume INTEGER, verdict TEXT, fragment INTEGER);
'''


class Record:
    __slots__ = ('phys', 'number', 'seq', 'lsn', 'base', 'base_seq', 'flags', 'names_json', 'attrs_json', 'ev',
                 'volume_name', '_names', '_attrs')

    def __init__(self, row):
        (self.phys, self.number, self.seq, self.lsn, self.base, self.base_seq, self.flags, self.names_json,
         self.attrs_json, self.ev, self.volume_name) = row
        self._names = self._attrs = None

    @property
    def names(self):
        if self._names is None:
            self._names = json.loads(self.names_json)
        return self._names

    @property
    def attrs(self):
        if self._attrs is None:
            self._attrs = json.loads(self.attrs_json)
        return self._attrs

    @property
    def in_use(self):
        return bool(self.flags & 1)

    @property
    def is_dir(self):
        return bool(self.flags & 2)


def load_records(index_db):
    return [Record(row) for row in index_db.execute(
        'SELECT phys, number, seq, lsn, base, base_seq, flags, names, attrs, ev, volume_name FROM records ORDER BY phys')]


def run_offset(runs, byte_offset, cluster_size):
    """Volume byte offset of attribute byte ``byte_offset`` through ``runs``, or None."""
    cluster, within = divmod(byte_offset, cluster_size)
    position = 0
    for lcn, count in runs or ():
        if position <= cluster < position + count:
            return None if lcn is None else (lcn + cluster - position) * cluster_size + within
        position += count
    return None


def raw_anchors(index_db, records, cluster_size):
    """(phys, volume_offset) pairs: INDX block <-> its directory's $I30 allocation run.

    Record numbers repeat across volumes (every root is record 5), so when
    several directory records share (number, sequence) the one whose MFT
    fragment also holds the children named in the INDX block is used; an
    undecidable block yields no anchor rather than a wrong one.
    """
    candidates = defaultdict(dict)  # (number, seq) -> {(key, runs_json): attr}
    by_number = defaultdict(dict)
    copies = defaultdict(list)      # number -> base-record copies (for child-name checks)
    for record in records:
        key = record.phys - record.number * RECORD_SIZE
        if not record.base:
            copies[record.number].append(record)
        if record.is_dir and not record.base:
            for attr in record.attrs:
                if attr['t'] == 0xA0 and attr['nr'] and attr.get('runs') and attr['n'] == '$I30':
                    runs = json.dumps(attr['runs'])
                    candidates[(record.number, record.seq)].setdefault((key, runs), attr)
                    by_number[record.number].setdefault((key, runs), attr)
    vcn_bytes = cluster_size if cluster_size <= 4096 else 512
    anchors = []
    for phys, vcn, parent, parent_seq in index_db.execute('SELECT phys, vcn, parent, parent_seq FROM indx WHERE parent IS NOT NULL'):
        options = candidates.get((parent, parent_seq)) or by_number.get(parent) or {}
        if len({runs for _, runs in options}) > 1:
            score = Counter()
            for child, child_seq, name in index_db.execute('SELECT child, child_seq, name FROM entries WHERE indx_phys=?', (phys,)):
                for copy in copies.get(child, ()):
                    if copy.seq == child_seq and any(n[0] == name and n[1] == parent for n in copy.names):
                        score[copy.phys - copy.number * RECORD_SIZE] += 1
            ranked = [(score.get(key, 0), key, runs) for key, runs in options]
            ranked.sort(reverse=True)
            if not ranked or ranked[0][0] == 0 or (len(ranked) > 1 and ranked[1][0] == ranked[0][0] and ranked[1][2] != ranked[0][2]):
                continue
            options = {(ranked[0][1], ranked[0][2]): options[(ranked[0][1], ranked[0][2])]}
        for attr in options.values():
            if not attr['svcn'] <= vcn <= attr['evcn']:
                continue
            offset = run_offset(attr['runs'], (vcn - attr['svcn']) * vcn_bytes, cluster_size)
            if offset is not None:
                anchors.append((phys, offset))
                break
    return anchors


def infer_cluster_size(index_db, records, override=None):
    """Pick the cluster size whose anchors concentrate on the fewest MiB residues."""
    boot = Counter(cs for (cs,) in index_db.execute('SELECT cluster_size FROM boot'))
    candidates = [override] if override else sorted(CLUSTER_CANDIDATES, key=lambda cs: (-boot.get(cs, 0), cs != 4096))
    report, best = [], None
    for cs in candidates:
        anchors = raw_anchors(index_db, records, cs)
        residues = Counter((phys - offset) % MiB for phys, offset in anchors)
        top = sum(n for _, n in residues.most_common(8))
        score = top / len(anchors) if anchors else 0.0
        report.append(dict(cluster_size=cs, anchors=len(anchors), concentration=round(score, 4), boot_sectors=boot.get(cs, 0)))
        key = (score >= 0.5 and len(anchors) >= 2, score * len(anchors), boot.get(cs, 0), cs == 4096)
        if best is None or key > best[0]:
            best = (key, cs, anchors)
    return best[1], best[2], dict(candidates=report, chosen=best[1],
                                  source='override' if override else 'boot_sector' if boot.get(best[1]) else 'anchor_concentration')


# ---------------------------------------------------------------------------
# Geometry fit per volume family
# ---------------------------------------------------------------------------
def unit_map(anchors, residue):
    """guest MiB unit (relative to P - residue) -> physical MiB, majority over anchors."""
    votes = defaultdict(Counter)
    for phys, offset in anchors:
        within = (residue + offset) % MiB
        if phys < within:
            continue
        votes[(residue + offset) // MiB][(phys - within) // MiB] += 1
    return {u: c.most_common(1)[0][0] for u, c in votes.items()}


def evaluate_hypothesis(units, h, k):
    """Return (refuted_units, supporting_blocks, block->start_pm) for block size h MiB, shift k."""
    blocks = defaultdict(Counter)
    subs = defaultdict(set)
    for u, pm in units.items():
        b, sub = divmod(u + k, h)
        if pm - sub < 0:
            blocks[b][None] += 1
            continue
        blocks[b][pm - sub] += 1
        subs[b].add(sub)
    refuted, support, starts = 0, 0, {}
    for b, counter in blocks.items():
        (start, agree), = counter.most_common(1)
        refuted += sum(counter.values()) - agree
        if start is None:
            continue
        starts[b] = start
        if h > 1 and agree >= 2 and min(subs[b]) < h // 2 <= max(subs[b]):
            support += 1
    return refuted, support, starts


def fit_geometry(units, *, header_score=None, hint_mib=None, override_mib=None, tolerance=0.01, min_support=3):
    """Choose block size (MiB) and shift k (P mod B = residue + k MiB). Reports every hypothesis tried.

    Too small a block size only costs evidence; too large a one maps whole
    blocks wrongly. So a size above 1 MiB needs: no anchor contradicting it,
    no more file-header mismatches than the 1 MiB baseline, and at least
    ``min_support`` blocks whose two halves are pinned by agreeing anchors
    (or the VHDX metadata table naming that size).
    """
    total = len(units)
    tried, feasible = [], {}
    sizes = [override_mib] if override_mib else BLOCK_CANDIDATES_MIB
    baseline_bad = None
    if header_score and not override_mib:
        _, _, starts = evaluate_hypothesis(units, 1, 0)
        baseline_bad = header_score(1, 0, starts)[1]
    for h in sizes:
        best = None
        for k in range(h):
            refuted, support, starts = evaluate_hypothesis(units, h, k)
            good, bad = header_score(h, k, starts) if header_score else (0, 0)
            ok = refuted <= tolerance * total and (baseline_bad is None or bad <= baseline_bad + max(1, tolerance * (good + bad)) - 1)
            key = (ok, -refuted, good - bad, support)
            if best is None or key > best[0]:
                best = (key, k, refuted, support, good, bad, ok)
        _, k, refuted, support, good, bad, ok = best
        tried.append(dict(block_mib=h, shift_mib=k, refuted_units=refuted, supporting_blocks=support,
                          header_matches=good, header_mismatches=bad, consistent=ok))
        if ok:
            feasible[h] = (k, support, good)
    if override_mib:
        chosen, reason = override_mib, 'override'
    elif hint_mib in feasible:
        chosen, reason = hint_mib, 'vhdx_metadata'
    else:
        supported = [h for h, (k, support, good) in feasible.items() if h == 1 or support >= min_support]
        chosen = max(supported) if supported else 1
        reason = 'largest_consistent_block_size_with_independent_support'
    k = feasible.get(chosen, (0, 0, 0))[0]
    return chosen, k, dict(units=total, tried=tried, chosen_block_mib=chosen, chosen_shift_mib=k, reason=reason,
                           min_support=min_support, ambiguous_shift=_shift_ambiguous(tried, chosen))


def _shift_ambiguous(tried, h):
    return False if h == 1 else not any(t['block_mib'] == h and (t['header_matches'] or t['supporting_blocks']) for t in tried)


# ---------------------------------------------------------------------------
# Volume maps
# ---------------------------------------------------------------------------
class VolumeMap:
    def __init__(self, volume, cluster_size, residue, block_size, shift, label=''):
        self.volume, self.cluster_size, self.residue = volume, cluster_size, residue
        self.block_size, self.shift, self.label = block_size, shift, label
        self.blocks = {}  # block -> [start, method, matched, expected, needed]
        self.unresolved = {}  # needed block -> references, no mapping found

    def locate(self, offset):
        """Volume byte offset -> (guest block, offset in block)."""
        return divmod(self.shift + offset, self.block_size)

    def phys(self, offset, trusted_only=True, trusted=TRUSTED):
        block, within = self.locate(offset)
        entry = self.blocks.get(block)
        if entry is None or (trusted_only and entry[1] not in trusted):
            return None
        return entry[0] + within

    def pieces(self, runs, size, trusted=TRUSTED):
        """Physical (offset or None for sparse, length) pieces for a data runlist, or (None, reason)."""
        pieces, remaining, cs, methods = [], size, self.cluster_size, set()
        for lcn, count in runs:
            if remaining <= 0:
                break
            length = min(count * cs, remaining)
            if lcn is None:
                pieces.append((None, length))
                remaining -= length
                continue
            offset = lcn * cs
            while length > 0:
                block, within = self.locate(offset)
                take = min(length, self.block_size - within)
                entry = self.blocks.get(block)
                if entry is None:
                    return None, 'unmapped_block', block
                if entry[1] not in trusted:
                    return None, 'unverified_block_mapping', block
                methods.add(entry[1])
                pieces.append((entry[0] + within, take))
                offset += take
                length -= take
                remaining -= take
        if remaining > 0:
            return None, 'runlist_shorter_than_size', None
        return pieces, sorted(methods), None


def data_runs(record, extensions):
    """Combined unnamed $DATA runs (base + extension records) or a reason string."""
    parts = {}
    for attr in record.attrs:
        if attr['t'] == 0x80 and not attr['n']:
            if not attr['nr']:
                return dict(resident=True, size=attr['size'])
            parts[attr['svcn']] = attr
    for ext in extensions:
        for attr in ext.attrs:
            if attr['t'] == 0x80 and not attr['n'] and attr['nr']:
                parts.setdefault(attr['svcn'], attr)
    if 0 not in parts:
        return dict(error='no_data_attribute' if not record.has_list else 'missing_extension_record')
    first = parts[0]
    if first['fl'] & 0x4001:
        return dict(error='compressed_or_encrypted_attribute', size=first['size'])
    runs, expect = [], 0
    for svcn in sorted(parts):
        attr = parts[svcn]
        if svcn != expect or attr.get('runs') is None:
            return dict(error='missing_extension_record', size=first['size'])
        runs += attr['runs']
        expect = attr['evcn'] + 1
    return dict(runs=runs, size=first['size'], init=first.get('init', first['size']), flags=first['fl'])


def mft_layout(records, residue, cluster_size):
    """MiB residues of (phys - number*1024) for this family's own MFT runs.

    $MFT record 0 copies whose position fits family ``residue`` give the MFT
    runlist; record n then sits at P + run_lcn*cs + (n*1024 - run_vcn*cs).
    """
    layout = {residue}
    for record in records:
        if record.number != 0 or record.base or not any(n[0] == '$MFT' for n in record.names):
            continue
        for attr in record.attrs:
            if attr['t'] == 0x80 and not attr['n'] and attr['nr'] and attr.get('svcn') == 0 and attr.get('runs'):
                first = attr['runs'][0][0]
                if first is None or (record.phys - first * cluster_size) % MiB != residue:
                    break
                vcn = 0
                for lcn, count in attr['runs']:
                    if lcn is not None:
                        layout.add((residue + (lcn - vcn) * cluster_size) % MiB)
                    vcn += count
                break
    return layout


def fragments(records):
    """Physically contiguous MFT runs: records n, n+1... 1 KiB apart (same phys - n*1024)."""
    groups, current = [], None
    for record in records:  # sorted by phys
        key = record.phys - record.number * RECORD_SIZE
        if current and key == current['key'] and record.phys - current['end'] <= 4 * MiB:
            current['end'] = record.phys
            current['records'].append(record)
        else:
            current = dict(key=key, start=record.phys, end=record.phys, records=[record])
            groups.append(current)
    return groups


class Rebuilder:
    """Evidence -> volumes, block maps and record membership."""

    def __init__(self, index_db, magic, *, zeros=(), source_size=None, damaged=(), options=None, ctx=None):
        self.db, self.magic, self.zeros = index_db, magic, zeros
        self.size, self.damaged = source_size, list(damaged)
        self.options = dict(options or {})
        self.ctx = ctx
        self.report = {}

    def log(self, text):
        if self.ctx:
            self.ctx.log(text)

    def tick(self, done, total):
        if self.ctx:
            self.ctx.check_cancel()
            self.ctx.advance(done, total=total)

    # --- expectations helpers -----------------------------------------
    @staticmethod
    def typed_starts(records, cluster_size):
        out = []
        for record in records:
            if not record.in_use or record.is_dir or record.base:
                continue
            name = primary_name(record.names)
            kind = expected_type(name[0]) if name else None
            if not kind:
                continue
            for attr in record.attrs:
                if attr['t'] == 0x80 and not attr['n'] and attr['nr'] and attr.get('svcn') == 0 and attr.get('runs') and attr['runs'][0][0]:
                    if not attr['fl'] & 0x4001:
                        out.append((attr['runs'][0][0] * cluster_size, kind))
                    break
        return out

    def header_ratio(self, vmap, records, trusted_only=False):
        checks = ok = 0
        for offset, kind in self.typed_starts(records, vmap.cluster_size):
            phys = vmap.phys(offset, trusted_only=trusted_only)
            if phys is None:
                continue
            checks += 1
            ok += self.magic.get(phys) == kind
        return checks, ok

    # --- main -----------------------------------------------------------
    def run(self):
        started = time.monotonic()
        records = load_records(self.db)
        self.records = records
        self.tick(1, 6)
        cs, anchors, cluster_report = infer_cluster_size(self.db, records, self.options.get('cluster_size'))
        self.report['cluster'] = cluster_report
        self.log(f'cluster size {cs}; {len(anchors)} anchors')
        hint = Counter(b // MiB for (b,) in self.db.execute('SELECT block_size FROM vhdx_meta') if b)
        hint_mib = hint.most_common(1)[0][0] if hint else None
        self.report['vhdx_metadata_block_mib'] = hint_mib
        families = Counter((phys - offset) % MiB for phys, offset in anchors)
        minimum = max(2, int(0.005 * len(anchors)))
        frags = fragments(records)
        self.tick(2, 6)
        volumes, maps = [], []
        for residue, count in families.most_common():
            if count < minimum or len(volumes) >= int(self.options.get('max_volumes', 8)):
                break
            fam_anchors = [(p, o) for p, o in anchors if (p - o) % MiB == residue]
            units = unit_map(fam_anchors, residue)
            layout = mft_layout(records, residue, cs)
            prior = [r for f in frags if (f['key'] % MiB) in layout for r in f['records']]
            typed = self.typed_starts(prior or records, cs)
            if len(typed) > 50000:  # the fit tries ~500 hypotheses; a deterministic sample keeps it bounded
                typed = typed[::len(typed) // 50000 + 1]

            def header_score(h, k, starts, typed=typed, residue=residue):
                good = bad = 0
                for offset, kind in typed:
                    u = (residue + offset) // MiB
                    b, sub = divmod(u + k, h)
                    if b in starts:
                        if self.magic.get((starts[b] + sub) * MiB + (residue + offset) % MiB) == kind:
                            good += 1
                        else:
                            bad += 1
                return good, bad

            override = self.options.get('block_size_mib')
            h, k, fit = fit_geometry(units, header_score=header_score, hint_mib=hint_mib, override_mib=override,
                                     min_support=int(self.options.get('min_block_support', 3)))
            vmap = VolumeMap(len(volumes) + 1, cs, residue, h * MiB, residue + k * MiB)
            vmap.layout = layout
            info = dict(residue=residue, anchors=count, fit=fit, prior_records=len(prior))
            volumes.append(info)
            maps.append((vmap, fam_anchors, prior or records))
        if not maps:
            raise ValueError('No consistent INDX anchors were found; the block map cannot be rebuilt from this evidence')
        self.tick(3, 6)
        # Pass 1: maps from prior-attributed records, then fragment membership.
        for vmap, fam_anchors, prior in maps:
            self.build(vmap, fam_anchors, prior)
        hook = getattr(self, 'membership_hook', None)
        if hook:
            hook()  # the caller shows "volume membership" as its own stage from here
        # Embedded images legitimately share slots with their host: classify before resolving conflicts.
        status = self.classify_volumes(maps)
        self.resolve_conflicts([m for m, _, _ in maps if status[m.volume] == 'volume'])
        membership, frag_report = self.membership(frags, [m for m, _, _ in maps], status)
        self.tick(4, 6)
        # Pass 2: rebuild every real volume from its member records only.
        members = defaultdict(list)
        for record in records:
            verdict = membership.get(record.phys)
            if verdict and verdict[1] in ('own', 'own_by_layout', 'own_by_slot'):
                members[verdict[0]].append(record)
        for vmap, fam_anchors, prior in maps:
            if status[vmap.volume] == 'volume':
                vmap.blocks.clear()
                vmap.unresolved.clear()
                self.build(vmap, fam_anchors, members.get(vmap.volume, []))
        real = [m for m, _, _ in maps if status[m.volume] == 'volume']
        self.resolve_conflicts(real)
        self.tick(5, 6)
        accuracy = self.interpolation_accuracy(real)
        for vmap in real:
            labels = Counter(r.volume_name for r in members.get(vmap.volume, []) if r.number == 3 and r.volume_name)
            name = labels.most_common(1)[0][0] if labels else ''
            vmap.label = f'卷{vmap.volume}' + (f'-{name}' if name else '')
        self.report.update(volumes=volumes, volume_status=status, membership=frag_report,
                           interpolation=accuracy, seconds=round(time.monotonic() - started, 3))
        self.maps, self.status, self.membership_map = maps, status, membership
        self.tick(6, 6)
        return self

    def build(self, vmap, fam_anchors, records):
        """Resolve every needed guest block of one volume (generalised bat_build)."""
        B, cs = vmap.block_size, vmap.cluster_size
        votes = defaultdict(Counter)
        for phys, offset in fam_anchors:
            block, within = vmap.locate(offset)
            if phys >= within:
                votes[block][phys - within] += 1
        anchor = {b: c.most_common(1)[0][0] for b, c in votes.items()}
        expect, needed = defaultdict(list), Counter()
        for offset, kind in self.typed_starts(records, cs):
            block, within = vmap.locate(offset)
            expect[block].append((within, kind))
        for record in records:
            if not record.in_use and record.is_dir:
                continue
            for attr in record.attrs:
                if attr['t'] not in (0x80, 0xA0) or not attr['nr'] or not attr.get('runs'):
                    continue
                if not record.in_use and (attr['t'] != 0x80 or attr['n']):
                    continue  # deleted files: only their unnamed data, so they can be checked and recovered
                for lcn, count in attr['runs']:
                    if lcn is None:
                        continue
                    first, _ = vmap.locate(lcn * cs)
                    last, _ = vmap.locate((lcn + count) * cs - 1)
                    for block in range(first, last + 1):
                        needed[block] += 1
        for block in anchor:
            needed.setdefault(block, 0)

        def score(block, start):
            exp = expect.get(block, ())
            return sum(self.magic.get(start + o) == t for o, t in exp), len(exp)

        keys = sorted(anchor)
        unresolved = {}
        for block in sorted(needed):
            if block in anchor:
                ok, n = score(block, anchor[block])
                if n < 3 or ok * 2 >= n:
                    vmap.blocks[block] = [anchor[block], 'anchor', ok, n, needed[block]]
                    continue
            i = bisect.bisect_left(keys, block)
            left = anchor[keys[i - 1]] + (block - keys[i - 1]) * B if i > 0 and keys[i - 1] != block else None
            j = bisect.bisect_right(keys, block)
            right = anchor[keys[j]] - (keys[j] - block) * B if j < len(keys) else None
            candidates = {c for c in (left, right) if c is not None and c >= 0}
            n = len(expect.get(block, ()))
            scored = sorted(((score(block, c), c) for c in candidates), reverse=True)
            if scored and n and scored[0][0][0] >= max(1, (n + 1) // 2) and (len(scored) == 1 or scored[1][0][0] < scored[0][0][0]):
                (ok, n), start = scored[0]
                vmap.blocks[block] = [start, 'interpolated_verified', ok, n, needed[block]]
                continue
            unresolved[block] = (left, right, n)
        # Global header search for blocks that still lack a mapping.
        wanted = {(o % MiB, t) for block, (_, _, n) in unresolved.items() if n >= 2 for o, t in expect[block][:12]}
        by_key = defaultdict(list)
        if wanted:
            for phys, kind in self.magic:
                key = (phys % MiB, kind)
                if key in wanted and len(by_key[key]) < 5000:
                    by_key[key].append(phys)
        for block, (left, right, n) in unresolved.items():
            if n >= 2:
                vote = Counter()
                for o, t in expect[block][:12]:
                    for phys in by_key.get((o % MiB, t), ()):
                        if phys >= o:
                            vote[phys - o] += 1
                if vote:
                    (start, v), *rest = vote.most_common(2)
                    second = rest[0][1] if rest else 0
                    if v >= max(2, (min(n, 12) + 1) // 2) and v > second:
                        vmap.blocks[block] = [start, 'searched_verified', v, min(n, 12), needed[block]]
                        continue
            if n == 0 and left is not None and left == right:
                vmap.blocks[block] = [left, 'interpolated_bracketed', 0, 0, needed[block]]
            elif n == 0 and (left is None) != (right is None):
                vmap.blocks[block] = [left if left is not None else right, 'interpolated_unverified', 0, 0, needed[block]]
            else:
                vmap.unresolved[block] = needed[block]  # files touching it are reported incomplete
        return vmap

    @staticmethod
    def resolve_conflicts(vmaps):
        """One physical slot holds one guest block: keep the strongest claim."""
        owner = defaultdict(list)
        for vmap in vmaps:
            for block, entry in vmap.blocks.items():
                owner[entry[0]].append((vmap, block))
        dropped = 0
        for start, claims in owner.items():
            if len(claims) > 1:
                claims.sort(key=lambda c: (RANK[c[0].blocks[c[1]][1]], c[0].blocks[c[1]][2], -c[0].volume), reverse=True)
                for vmap, block in claims[1:]:
                    vmap.unresolved[block] = vmap.blocks.pop(block)[4]
                    dropped += 1
        return dropped

    def file_intervals(self, vmap, records):
        """Physical intervals of large or disk-image files (system metafiles excluded)."""
        files = []
        for record in records:
            if not record.in_use or record.is_dir or record.base or record.number < 24:
                continue
            name = primary_name(record.names)
            image = bool(name and extension(name[0]) in IMAGE_EXTENSIONS)
            for attr in record.attrs:
                if not (attr['t'] == 0x80 and not attr['n'] and attr['nr'] and attr.get('runs')):
                    continue
                if attr['size'] < MiB and not image:
                    continue
                intervals = []
                for lcn, count in attr['runs']:
                    if lcn is None:
                        continue
                    offset, end = lcn * vmap.cluster_size, (lcn + count) * vmap.cluster_size
                    while offset < end:
                        block, within = vmap.locate(offset)
                        take = min(end - offset, vmap.block_size - within)
                        entry = vmap.blocks.get(block)
                        if entry is not None:
                            intervals.append([entry[0] + within, entry[0] + within + take])
                        offset += take
                if intervals:
                    files.append((image, _merge(sorted(intervals))))
        return files

    def classify_volumes(self, maps):
        """A family whose anchors mostly sit inside another family's files is an embedded disk image.

        Records inside disk-image files (by extension, or holding an embedded
        family's anchors) belong to another LCN space and are marked foreign.
        """
        per_family = {vmap.volume: self.file_intervals(vmap, records) for vmap, _, records in maps}
        status, embedded_in, image_intervals = {}, {}, []
        for vmap, fam_anchors, records in maps:
            status[vmap.volume] = 'volume'
            for other, files in per_family.items():
                if other == vmap.volume or not fam_anchors:
                    continue
                union = _merge(sorted(i for _, intervals in files for i in intervals))
                inside = sum(1 for phys, _ in fam_anchors if _inside(union, phys))
                if inside * 2 >= len(fam_anchors):
                    status[vmap.volume], embedded_in[vmap.volume] = 'embedded', other
                    for _, intervals in files:
                        if any(_inside(intervals, phys) for phys, _ in fam_anchors):
                            image_intervals += intervals
                    break
        for volume, files in per_family.items():
            if status[volume] == 'volume':
                image_intervals += [i for image, intervals in files if image for i in intervals]
        self.image_intervals = _merge(sorted(image_intervals))
        self.report['embedded_in'] = embedded_in
        return status

    def membership(self, frags, vmaps, status):
        """Fragment-level verdict: own / foreign / own_by_layout / own_by_slot / undetermined."""
        real = [v for v in vmaps if status[v.volume] == 'volume']
        slots = SlotIndex(real, trusted_only=False)
        result, verdicts = {}, Counter()
        for index, frag in enumerate(frags):
            ratios = []
            for vmap in real:
                checks, ok = self.header_ratio(vmap, frag['records'])
                ratios.append((checks, ok, vmap))
            decided = [(ok / checks, vmap) for checks, ok, vmap in ratios if checks >= 3]
            volume, verdict = None, 'undetermined'
            if _inside(getattr(self, 'image_intervals', []), frag['start']):
                verdict = 'foreign'
            elif any(r >= 0.8 for r, _ in decided):
                volume, verdict = max(decided, key=lambda x: x[0])[1].volume, 'own'
            elif decided and all(r <= 0.2 for r, _ in decided) and len(decided) == len(real):
                verdict = 'foreign'
            else:
                layout = [v for v in real if frag['key'] % MiB in getattr(v, 'layout', {v.residue})]
                if len(layout) == 1:
                    volume, verdict = layout[0].volume, 'own_by_layout'
                else:
                    owners = Counter(v for v in (slots.owner(r.phys) for r in frag['records']) if v is not None)
                    if owners:
                        volume, verdict = owners.most_common(1)[0][0], 'own_by_slot'
                    elif len(real) == 1 and not decided:
                        volume, verdict = real[0].volume, 'own_by_slot'
            verdicts[verdict] += len(frag['records'])
            for record in frag['records']:
                result[record.phys] = (volume, verdict, index)
        return result, dict(fragments=len(frags), records_by_verdict=dict(verdicts))

    def interpolation_accuracy(self, vmaps, min_samples=20):
        """Leave-one-out test of bracketed interpolation on verified blocks, by neighbour distance."""
        buckets = (1, 2, 4, 8, 16, 64, 256, 1 << 40)
        right, wrong = Counter(), Counter()
        for vmap in vmaps:
            verified = sorted((b, e[0]) for b, e in vmap.blocks.items() if e[1] == 'anchor' or (e[1] in TRUSTED and e[2] >= 1))
            B = vmap.block_size
            for i in range(1, len(verified) - 1):
                (lb, ls), (b, s), (rb, rs) = verified[i - 1], verified[i], verified[i + 1]
                pl, pr = ls + (b - lb) * B, rs - (rb - b) * B
                if pl != pr:
                    continue
                d = next(x for x in buckets if max(b - lb, rb - b) <= x)
                (right if pl == s else wrong)[d] += 1
        trusted, cumulative, cumulative_wrong = 0, 0, 0
        for d in buckets:
            cumulative += right[d] + wrong[d]
            cumulative_wrong += wrong[d]
            if cumulative_wrong:
                break
            if cumulative >= min_samples and right[d] + wrong[d]:
                trusted = d
        promoted = 0
        if trusted:
            for vmap in vmaps:
                keys = sorted(b for b, e in vmap.blocks.items() if e[1] in TRUSTED)
                for block, entry in vmap.blocks.items():
                    if entry[1] != 'interpolated_bracketed':
                        continue
                    i = bisect.bisect_left(keys, block)
                    if not (0 < i < len(keys)) or max(block - keys[i - 1], keys[i] - block) > trusted:
                        continue
                    # Held to the measured condition: both trusted neighbours predict this exact start.
                    lower, upper = keys[i - 1], keys[i]
                    pl = vmap.blocks[lower][0] + (block - lower) * vmap.block_size
                    pr = vmap.blocks[upper][0] - (upper - block) * vmap.block_size
                    if pl == pr == entry[0]:
                        entry[1] = 'interpolated_tested'
                        promoted += 1
        return dict(by_distance={str(d): dict(correct=right[d], wrong=wrong[d]) for d in buckets if right[d] + wrong[d]},
                    trusted_max_distance=trusted, promoted_bracketed_blocks=promoted, min_samples=min_samples)

    # --- persistence ------------------------------------------------------
    def save(self, path):
        path = Path(path)
        temporary = path.with_name(path.name + '.tmp')
        if temporary.exists():
            temporary.unlink()
        db = sqlite3.connect(str(temporary))
        db.executescript(SCHEMA)
        with db:
            for vmap, fam_anchors, prior in self.maps:
                db.execute('INSERT INTO volumes VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (vmap.volume, vmap.label or f'卷{vmap.volume}', self.status[vmap.volume], vmap.cluster_size,
                            vmap.residue, vmap.block_size, vmap.shift, len(fam_anchors), 0, '{}'))
                db.executemany('INSERT INTO blocks VALUES(?,?,?,?,?,?,?)',
                               [(vmap.volume, b, *e) for b, e in vmap.blocks.items()])
                db.executemany('INSERT OR IGNORE INTO blocks VALUES(?,?,NULL,?,0,0,?)',
                               [(vmap.volume, b, 'unresolved', n) for b, n in vmap.unresolved.items()])
            db.executemany('INSERT INTO membership VALUES(?,?,?,?)',
                           [(phys, volume, verdict, frag) for phys, (volume, verdict, frag) in self.membership_map.items()])
            db.execute('INSERT INTO meta VALUES(?,?)', ('report', json.dumps(self.report, default=str)))
            db.execute('INSERT INTO meta VALUES(?,?)', ('image_intervals', json.dumps(getattr(self, 'image_intervals', []))))
            db.execute('INSERT INTO meta VALUES(?,?)', ('status', json.dumps('finished')))
        db.close()
        from revivex_stage import replace_with_retry
        replace_with_retry(temporary, path)


class SlotIndex:
    """Physical offset -> owning volume through mapped block slots (bisect, no per-MiB tables)."""

    def __init__(self, vmaps, trusted_only=True):
        spans = []
        for vmap in vmaps:
            for block, entry in vmap.blocks.items():
                if entry[0] is not None and (not trusted_only or entry[1] in TRUSTED):
                    spans.append((entry[0], entry[0] + vmap.block_size, vmap.volume, block))
        spans.sort()
        self.starts = [s[0] for s in spans]
        self.spans = spans

    def lookup(self, phys):
        i = bisect.bisect_right(self.starts, phys) - 1
        if i >= 0 and phys < self.spans[i][1]:
            return self.spans[i]
        return None

    def owner(self, phys):
        span = self.lookup(phys)
        return span[2] if span else None

    def overlaps(self, start, end):
        i = bisect.bisect_right(self.starts, start) - 1
        i = max(i, 0)
        while i < len(self.spans) and self.spans[i][0] < end:
            if self.spans[i][1] > start:
                return True
            i += 1
        return False


def _merge(intervals):
    merged = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return merged


def _inside(intervals, phys):
    i = bisect.bisect_right(intervals, [phys, float('inf')]) - 1
    return i >= 0 and intervals[i][0] <= phys < intervals[i][1]


def load_maps(path):
    """Read map.sqlite -> ({volume: VolumeMap}, membership dict, report)."""
    db = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        maps = {}
        for vid, label, status, cs, residue, block, shift, *_ in db.execute('SELECT * FROM volumes'):
            if status != 'volume':
                continue
            maps[vid] = VolumeMap(vid, cs, residue, block, shift, label)
        for vid, block, start, method, matched, expected, needed in db.execute('SELECT * FROM blocks'):
            if vid in maps:
                if start is None:
                    maps[vid].unresolved[block] = needed
                else:
                    maps[vid].blocks[block] = [start, method, matched, expected, needed]
        membership = {phys: (vid, verdict) for phys, vid, verdict, _ in db.execute('SELECT * FROM membership')}
        row = db.execute("SELECT value FROM meta WHERE key='report'").fetchone()
        report = json.loads(row[0]) if row else {}
        row = db.execute("SELECT value FROM meta WHERE key='image_intervals'").fetchone()
        report['image_intervals'] = json.loads(row[0]) if row else []
        return maps, membership, report
    finally:
        db.close()


def map_finished(path):
    path = Path(path)
    if not path.is_file():
        return False
    try:
        db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True)
        try:
            row = db.execute("SELECT value FROM meta WHERE key='status'").fetchone()
            return bool(row and json.loads(row[0]) == 'finished')
        finally:
            db.close()
    except sqlite3.Error:
        return False
