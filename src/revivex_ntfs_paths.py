"""Infer candidate NTFS paths from ONE source's physical record index.

This is an optional browsing aid, never volume identification or VHDX mapping.
Even an unambiguous chain can join unrelated record fragments in a raw image;
all successful paths are therefore explicitly inferred and unverified.
"""
import json
from collections import defaultdict
from pathlib import Path


class UnknownPath(ValueError):
    pass


def infer_paths(records, source_id, *, max_depth=256, max_paths_per_record=256):
    """Return {physical_offset: [link outcomes]} for a single source index.

    Call separately for each source manifest, using that source's unique catalog
    identifier, not its basename. Never concatenate different source indexes.
    Every FILE_NAME link, including DOS namespace and hard links, is retained.
    Successful paths use '/' separators and are display-only, not export paths.
    """
    if not isinstance(source_id, str) or not source_id:
        raise ValueError("A nonempty source identifier is required")
    if not 1 <= max_depth <= 256 or max_paths_per_record < 1:
        raise ValueError("Invalid path inference limits")
    records = list(records)
    by_key = defaultdict(list)
    by_number = defaultdict(list)
    by_offset = defaultdict(list)
    for record in records:
        if not isinstance(record, dict) or record.get("status") != "validated_record":
            continue
        if not all(isinstance(record.get(field), int) and not isinstance(record[field], bool) and record[field] >= 0
                   for field in ("offset", "record_number", "sequence")):
            continue
        by_offset[record["offset"]].append(record)
        if record.get("source_id", source_id) != source_id:
            continue
        key = (record["record_number"], record["sequence"])
        by_key[key].append(record)
        by_number[key[0]].append(record)

    def checked_name(link):
        name = link.get("name")
        # Unescaped separators would forge a plausible directory tree.
        if not isinstance(name, str) or not name or name in (".", "..") or any(c in name for c in ("/", "\\", "\x00")):
            raise UnknownPath("unsafe_or_missing_name")
        if any(ord(c) < 32 for c in name):
            raise UnknownPath("unsafe_or_missing_name")
        return name

    def parent_for(link):
        number, sequence = link.get("parent_record"), link.get("parent_sequence")
        if not isinstance(number, int) or not isinstance(sequence, int) or sequence <= 0:
            raise UnknownPath("missing_parent_reference")
        matches = by_key.get((number, sequence), [])
        if not matches:
            raise UnknownPath("stale_parent_sequence" if number in by_number else "parent_not_found")
        if len(matches) != 1:
            raise UnknownPath("ambiguous_parent_record")
        parent = matches[0]
        if len(by_offset[parent["offset"]]) != 1:
            raise UnknownPath("ambiguous_physical_offset")
        if parent.get("base_record_reference", 0):
            raise UnknownPath("extension_record_not_resolved")
        if not parent.get("directory") or not parent.get("in_use"):
            raise UnknownPath("parent_not_live_directory")
        return parent

    def directory_paths(record, visited, depth):
        key = (record["record_number"], record["sequence"])
        if key in visited:
            raise UnknownPath("parent_cycle")
        if depth >= max_depth:
            raise UnknownPath("depth_limit")
        if record["record_number"] == 5:
            return [()]
        links = record.get("file_names") or []
        if not links:
            raise UnknownPath("parent_has_no_names")
        paths = []
        # Reject unresolved parent alternatives rather than silently choosing a link.
        for link in links:
            if not isinstance(link, dict):
                raise UnknownPath("invalid_filename_metadata")
            name = checked_name(link)
            parent = parent_for(link)
            for base in directory_paths(parent, visited | {key}, depth + 1):
                paths.append((*base, name))
                if len(paths) > max_paths_per_record:
                    raise UnknownPath("path_expansion_limit")
        return paths

    output = {}
    for offset, matches in by_offset.items():
        outcomes = []
        for record in matches:
            links = record.get("file_names") or [None]
            for link in links:
                result = {"source_id": source_id, "file_name": link, "path": None,
                          "path_status": "path_unknown", "reason": None}
                try:
                    if record.get("source_id", source_id) != source_id:
                        raise UnknownPath("source_mismatch")
                    key = (record["record_number"], record["sequence"])
                    if len(matches) != 1:
                        raise UnknownPath("ambiguous_physical_offset")
                    if len(by_key[key]) != 1:
                        raise UnknownPath("ambiguous_record_identity")
                    if record.get("base_record_reference", 0):
                        raise UnknownPath("extension_record_not_resolved")
                    if not record["sequence"]:
                        raise UnknownPath("missing_record_sequence")
                    if not isinstance(link, dict):
                        raise UnknownPath("missing_filename_metadata")
                    if record["record_number"] == 5:
                        if not record.get("directory") or not record.get("in_use"):
                            raise UnknownPath("root_not_live_directory")
                        paths = [()]
                    else:
                        name = checked_name(link)
                        parent = parent_for(link)
                        paths = [(*base, name) for base in directory_paths(parent, {key}, 0)]
                    if len(outcomes) + len(paths) > max_paths_per_record:
                        raise UnknownPath("path_expansion_limit")
                    for path in paths:
                        outcomes.append({**result, "path": "/" + "/".join(path),
                                         "path_status": "inferred_unverified",
                                         "reason": "unique_metadata_chain_only_no_validated_volume_mapping"})
                except UnknownPath as error:
                    outcomes.append({**result, "reason": str(error)})
        output[offset] = outcomes
    return output


def load_record_paths(index_path, source_id, *, max_records=1000000,
                      max_index_bytes=256 * 1024 * 1024, **options):
    """Read a bounded single-source JSONL record index and infer display paths."""
    path = Path(index_path)
    if max_records < 1 or max_index_bytes < 1:
        raise ValueError("Index limits must be positive")
    if path.stat().st_size > max_index_bytes:
        raise ValueError("Record index exceeds size limit")
    records = []
    consumed = 0
    with path.open("rb") as stream:
        for line_number, line in enumerate(stream, 1):
            consumed += len(line)
            if line_number > max_records or consumed > max_index_bytes:
                raise ValueError("Record index exceeds configured limits")
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("Record index entry must be an object")
            records.append(record)
    return infer_paths(records, source_id, **options)
