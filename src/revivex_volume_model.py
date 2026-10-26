"""One NTFS volume's records, index entries and strict original paths.

Strict paths (field lesson 8): a parent is used only when a record copy or an
index entry with the SAME sequence number exists and is a directory. A reused
or foreign record is never borrowed; such paths start at
``_上级目录名丢失_<record>`` (labelled with known child names) instead.
"""
from __future__ import annotations

import bisect
from collections import Counter, defaultdict
import re

from revivex_block_map import Record, SlotIndex, _inside, data_runs, load_records
from revivex_ntfs_evidence import primary_name

OWN = ('own', 'own_by_layout', 'own_by_slot')
UNKNOWN_PARENT = '_上级目录名丢失_'
_UNSAFE = re.compile(r'[<>:"\\|?*\x00-\x1f]')
_RESERVED = re.compile(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)', re.I)
SYSTEM_PREFIXES = ('windows/', 'program files', 'programdata/', '$recycle.bin', 'system volume information',
                   'recovery/', 'perflogs/', '$windows.~', 'msocache/', 'boot/', 'users/default/', 'pagefile.sys',
                   'hiberfil.sys', 'swapfile.sys')


def safe_component(part, limit=200):
    part = _UNSAFE.sub('_', part).rstrip(' .') or '_'
    if part in ('.', '..'):
        part = '_' + part
    if _RESERVED.match(part):
        part = '_' + part
    encoded = part.encode('utf-8')
    if len(encoded) > limit:
        part = encoded[:limit].decode('utf-8', 'ignore').rstrip(' .') or '_'
    return part


class VolumeModel:
    def __init__(self, vmap, records, membership, entries, image_intervals=(), slots=None):
        self.vmap = vmap
        self.copies, self.extensions = defaultdict(list), defaultdict(list)
        for record in records:
            volume, verdict = membership.get(record.phys, (None, None))
            if volume != vmap.volume or verdict not in OWN:
                continue
            (self.extensions[record.base] if record.base else self.copies[record.number]).append((verdict == 'own', record))
        self.best = {n: max(c, key=lambda x: (x[0], x[1].lsn))[1] for n, c in self.copies.items()}
        self.entries, self.has_children = defaultdict(list), set()
        slots = slots or SlotIndex([vmap], trusted_only=False)
        dropped = 0
        for child, child_seq, parent, parent_seq, ns, name, indx_phys in entries:
            if ns == 2:
                continue  # DOS short names
            if _inside(image_intervals, indx_phys) or slots.owner(indx_phys) != vmap.volume:
                dropped += 1
                continue
            self.entries[(child, child_seq)].append((ns, name, parent, parent_seq))
            self.has_children.add((parent, parent_seq))
        self.dropped_entries = dropped
        self._cache = {}
        self._children = defaultdict(Counter)

    # --- records ---------------------------------------------------------
    def record_for(self, number, seq=None):
        copies = self.copies.get(number)
        if not copies:
            return None
        if seq is not None:
            same = [c for c in copies if c[1].seq == seq]
            return max(same, key=lambda x: (x[0], x[1].lsn))[1] if same else None
        return self.best[number]

    def extension_records(self, record):
        newest = {}
        for own, ext in self.extensions.get(record.number, ()):
            if ext.base_seq not in (0, record.seq):
                continue
            key = (own, ext.lsn)
            if ext.number not in newest or key > newest[ext.number][0]:
                newest[ext.number] = (key, ext)
        return [ext for _, ext in newest.values()]

    def data(self, record):
        return data_runs(record, self.extension_records(record))

    # --- strict paths ------------------------------------------------------
    def _lookup(self, number, seq, need_dir):
        same = [c[1] for c in self.copies.get(number, ()) if seq is None or c[1].seq == seq]
        if same:
            if need_dir:
                same = [r for r in same if r.is_dir]
                if not same:
                    return None  # that record is a file, so it cannot be anyone's folder
            name = primary_name(max(same, key=lambda r: r.lsn).names)
            if name:
                return name[0], name[1], name[2]
        options = self.entries.get((number, seq)) if seq is not None else None
        if options and (not need_dir or (number, seq) in self.has_children):
            ns, name, parent, parent_seq = max(options, key=lambda e: e[0] in (1, 3))
            return name, parent, parent_seq
        return None

    def strict_path(self, number, seq=None, need_dir=False, depth=0, seen=frozenset()):
        """[('UNKNOWN', n), name, ...] or [name, ...] from the root (record 5)."""
        if number == 5:
            return []
        key = (number, seq, need_dir)
        if key in self._cache:
            return self._cache[key]
        found = self._lookup(number, seq, need_dir) if depth < 64 and number not in seen else None
        if found is None or found[1] == number or found[1] in seen:
            value = [('UNKNOWN', number)]  # missing, too deep, or a parent cycle (A -> B -> A)
        else:
            name, parent, parent_seq = found
            value = self.strict_path(parent, parent_seq, True, depth + 1, seen | {number}) + [name]
        self._cache[key] = value  # records on a cycle never reach the root, so UNKNOWN is right for all of them
        return value

    def note_children(self, parts):
        if parts and isinstance(parts[0], tuple) and len(parts) > 2:
            self._children[parts[0][1]][parts[1]] += 1

    def unknown_label(self, number):
        top = [safe_component(c)[:16] for c, _ in self._children[number].most_common(3)]
        return f'{UNKNOWN_PARENT}{number}' + ('_含-' + '-'.join(top) if top else '')

    def display_path(self, parts):
        """(original path string, path_known flag)."""
        if parts and isinstance(parts[0], tuple):
            return '/'.join([self.unknown_label(parts[0][1])] + [str(p) for p in parts[1:]]), False
        return '/'.join(parts), True

    def output_parts(self, parts, number):
        if parts and isinstance(parts[0], tuple):
            safe = [self.unknown_label(parts[0][1])] + [safe_component(p) for p in parts[1:]]
        else:
            safe = [safe_component(p) for p in parts]
        return safe or [f'record_{number}']

    # --- files -------------------------------------------------------------
    def file_records(self):
        """In-use, non-directory user records (system metafiles 0-15 excluded)."""
        for number, record in self.best.items():
            if record.in_use and not record.is_dir and number >= 16:
                yield number, record

    def deleted_records(self):
        """Deleted (not in use) file records whose newest copy is still the deleted one."""
        for number, record in self.best.items():
            if not record.in_use and not record.is_dir and number >= 16 and record.names:
                yield number, record

    def _allocated(self):
        """Merged cluster intervals owned by in-use records (data, indexes and metafiles)."""
        if getattr(self, '_allocated_cache', None) is None:
            spans = []
            live = [r for r in self.best.values() if r.in_use]
            live += [ext for own, ext in (e for exts in self.extensions.values() for e in exts)
                     if self.best.get(ext.base) is not None and self.best[ext.base].in_use]
            for record in live:
                for attr in record.attrs:
                    if attr['nr'] and attr.get('runs'):
                        spans += [(lcn, lcn + count) for lcn, count in attr['runs'] if lcn is not None]
            merged = []
            for start, end in sorted(spans):
                if merged and start <= merged[-1][1]:
                    merged[-1][1] = max(merged[-1][1], end)
                else:
                    merged.append([start, end])
            self._allocated_cache = ([m[0] for m in merged], merged)
        return self._allocated_cache

    def clusters_reused(self, runs):
        """True when any cluster of a deleted file now belongs to a live file."""
        starts, merged = self._allocated()
        for lcn, count in runs:
            if lcn is None:
                continue
            i = bisect.bisect_right(starts, lcn + count - 1) - 1
            if i >= 0 and merged[i][1] > lcn:
                return True
        return False


def load_entries(index_db):
    return index_db.execute('SELECT child, child_seq, parent, parent_seq, ns, name, indx_phys FROM entries')


def build_models(index_db, maps, membership, report):
    records = load_records(index_db)
    slots = SlotIndex(list(maps.values()), trusted_only=False)
    entries = list(load_entries(index_db))
    intervals = report.get('image_intervals', [])
    return {vid: VolumeModel(vmap, records, membership, entries, intervals, slots) for vid, vmap in maps.items()}


def is_system_path(path):
    return path.lower().startswith(SYSTEM_PREFIXES)
