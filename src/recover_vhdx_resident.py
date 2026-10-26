"""Bounded, read-only physical NTFS resident-record salvage; not VHDX repair."""
import argparse
import errno
import hashlib
import json
import os
import re
import struct
from pathlib import Path

from dissect.ntfs.mft import MftRecord

from revivex_source_io import BoundedSource, SourceChangedError, stat_identity

SCHEMA_VERSION = 1
CAPABILITIES = {
    "source_access": "read_only", "scan_address_space": "physical_bytes",
    "record_bytes": 1024, "sector_bytes": 512, "alignment_bytes": 512,
    "resident_stream_export": True, "nonresident_stream_export": False,
    "vhdx_mapping_validated": False, "original_directory_reconstruction": False,
    "decryption": False,
}
WARNING = ("Partial salvage, not decryption or VHDX repair. Only structurally validated "
           "1024-byte NTFS FILE records with 512-byte sectors are supported. Resident data has "
           "no original-content checksum; deleted records may be stale. Physical candidates and "
           "parent references do not establish a volume or original paths. Nonresident streams "
           "are not extracted. Use an immutable source copy while scanning. "
           "Do not execute recovered files without malware scanning.")


def attributes(data):
    position = struct.unpack_from("<H", data, 20)[0]
    used = struct.unpack_from("<I", data, 24)[0]
    while position + 4 <= used:
        kind = struct.unpack_from("<I", data, position)[0]
        if kind == 0xFFFFFFFF:
            return
        length = struct.unpack_from("<I", data, position + 4)[0]
        yield position, kind, data[position:position + length]
        position += length


def parse_record(raw):
    if len(raw) != 1024 or raw[:4] != b"FILE":
        raise ValueError("Not a supported 1024-byte FILE record")
    usa_offset, usa_count = struct.unpack_from("<HH", raw, 4)
    attr_offset, flags, used, allocated = struct.unpack_from("<HHII", raw, 20)
    if allocated != 1024 or not 56 <= attr_offset < used <= 1024 or attr_offset % 8:
        raise ValueError("Invalid record bounds")
    if usa_count != 3 or not 48 <= usa_offset <= attr_offset - 6 or usa_offset % 2:
        raise ValueError("Invalid update sequence bounds")
    sequence = raw[usa_offset:usa_offset + 2]
    if any(raw[end - 2:end] != sequence for end in (512, 1024)):
        raise ValueError("Sector fixup mismatch")
    # Validate before handing attributes to the external decoder.
    fixed = bytearray(raw)
    for index, end in enumerate((512, 1024), 1):
        fixed[end - 2:end] = raw[usa_offset + 2 * index:usa_offset + 2 * index + 2]
    position = attr_offset
    while position + 4 <= used:
        kind = struct.unpack_from("<I", fixed, position)[0]
        if kind == 0xFFFFFFFF:
            return MftRecord.from_bytes(raw), flags
        if position + 16 > used:
            raise ValueError("Truncated attribute")
        length = struct.unpack_from("<I", fixed, position + 4)[0]
        nonresident, name_length, name_offset = struct.unpack_from("<BBH", fixed, position + 8)
        minimum = 64 if nonresident else 24
        if nonresident not in (0, 1) or length < minimum or length % 8 or position + length > used:
            raise ValueError("Invalid attribute bounds")
        if name_length and (name_offset < minimum or name_offset + name_length * 2 > length):
            raise ValueError("Invalid attribute name bounds")
        if name_length:
            fixed[position + name_offset:position + name_offset + name_length * 2].decode("utf-16le")
        if not nonresident:
            value_length, value_offset = struct.unpack_from("<IH", fixed, position + 16)
            if value_offset < 24 or value_offset + value_length > length:
                raise ValueError("Invalid resident value bounds")
            if name_length and value_offset < name_offset + name_length * 2:
                raise ValueError("Overlapping resident name and value")
            if kind == 0x30:
                value = fixed[position + value_offset:position + value_offset + value_length]
                if len(value) < 66 or value[65] > 3 or 66 + value[64] * 2 > len(value):
                    raise ValueError("Invalid FILE_NAME value")
                value[66:66 + value[64] * 2].decode("utf-16le")
        position += length
    raise ValueError("Missing attribute terminator")


def portable_basename(name, max_bytes=240):
    """Bound the whole component, including prefixes, for UTF-8 and NTFS.

    UTF-8 bytes also upper-bound UTF-16 code units for valid Unicode, so this
    conservative budget satisfies both common 255-byte and 255-unit limits.
    Original Unicode names remain unchanged in metadata.
    """
    return name.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore").rstrip(" .") or "unnamed"


def safe_name(name):
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).rstrip(" .")[:100].rstrip(" .")
    if name.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        name = "_" + name
    return portable_basename(name)


def file_names(record):
    links = []
    for position, kind, attr in attributes(record.data):
        if kind != 0x30 or attr[8]:
            continue
        size, start = struct.unpack_from("<IH", attr, 16)
        value = attr[start:start + size]
        parent = struct.unpack_from("<Q", value)[0]
        links.append({"name": value[66:66 + value[64] * 2].decode("utf-16le"),
                      "namespace": value[65], "parent_record": parent & ((1 << 48) - 1),
                      "parent_sequence": parent >> 48, "attribute_offset": position,
                      "attribute_id": struct.unpack_from("<H", attr, 14)[0],
                      "metadata_hex": value.hex()})
    return links


def identity(stat):
    return {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns,
            "device": stat.st_dev, "inode": stat.st_ino}


def durable_json(path, report):
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(report, stream, ensure_ascii=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def recover(source, output, *, max_candidates=1000000, max_output_bytes=1024 * 1024 * 1024,
            max_scan_bytes=None, cancelled=None):
    source, output = Path(source), Path(output)
    if max_candidates <= 0 or max_output_bytes < 0 or (max_scan_bytes is not None and max_scan_bytes < 0):
        raise ValueError("Invalid resource limit")
    if output.exists() or any(parent.is_symlink() for parent in [output, *output.parents]):
        raise ValueError("Output must be a new directory without symlink ancestors")
    if not source.is_file():
        raise ValueError("Source must be a regular file")
    original = source.stat()
    output.mkdir(parents=True)
    counts = dict.fromkeys(("aligned_candidates", "valid_records", "invalid_records", "directories",
                           "nonresident_streams", "resident_streams", "recovered_bytes", "export_failures"), 0)
    report = {"schema": "revivex.ntfs-resident", "schema_version": SCHEMA_VERSION,
              "source": str(source.resolve()), "source_size": original.st_size,
              "source_identity": identity(original), "source_identity_kind": "filesystem_stat_not_content_hash",
              "capabilities": CAPABILITIES, "output_path_base": "manifest_directory",
              "record_index": "record_index.jsonl", "status": "running", "counts": counts,
              "limits": {"max_candidates": max_candidates, "max_output_bytes": max_output_bytes,
                         "max_scan_bytes": max_scan_bytes}, "warning": WARNING, "files": []}
    manifest = output / "recovery_manifest.json"
    durable_json(manifest, report)
    try:
        with BoundedSource(source) as bounded, (output / "record_index.jsonl").open("x", encoding="utf-8") as index:
            if identity(bounded.opened_stat) != identity(original):
                raise ValueError("Source changed before scanning")
            image = bounded if original.st_size else None
            try:
                limit = min(original.st_size, max_scan_bytes) if max_scan_bytes is not None else original.st_size
                position = 0
                while image is not None and position < limit:
                    if cancelled and cancelled():
                        report["status"] = "cancelled"
                        break
                    # Bounded search windows permit cancellation even across large empty areas.
                    end = min(limit, position + 8 * 1024 * 1024)
                    offset = image.find(b"FILE", position, end)
                    if offset < 0:
                        position = end if end == limit else end - 3
                        continue
                    position = offset + 4
                    if offset % 512:
                        continue
                    if counts["aligned_candidates"] >= max_candidates:
                        report["status"] = "candidate_limit"
                        break
                    counts["aligned_candidates"] += 1
                    entry = {"offset": offset, "status": "invalid_record"}
                    try:
                        if offset + 1024 > limit:
                            raise ValueError("Record exceeds scan bounds")
                        record, flags = parse_record(image[offset:offset + 1024])
                        links = file_names(record)
                        chosen = min(links, key=lambda link: ({1: 0, 3: 1, 0: 2, 2: 3}[link["namespace"]], link["name"], link["parent_record"], link["parent_sequence"])) if links else None
                        name = chosen["name"] if chosen else "unnamed"
                        counts["valid_records"] += 1
                        directory = bool(flags & 2)
                        entry.update(status="validated_record", record_number=struct.unpack_from("<I", record.data, 44)[0],
                                     sequence=struct.unpack_from("<H", record.data, 16)[0],
                                     base_record_reference=struct.unpack_from("<Q", record.data, 32)[0],
                                     record_flags=flags, name=name,
                                     file_names=links, selected_file_name=chosen, in_use=bool(flags & 1),
                                     directory=directory, streams=[], unsupported_attributes=[])
                        counts["directories"] += int(directory)
                        for attr_position, kind, attr in attributes(record.data):
                            if kind != 0x80:
                                if kind == 0x20 or (kind == 0x30 and attr[8]):
                                    entry["unsupported_attributes"].append({"type": kind, "attribute_offset": attr_position, "reason": "attribute_list_or_nonresident_filename_not_resolved"})
                                continue
                            name_length, name_offset = struct.unpack_from("<BH", attr, 9)
                            stream_name = attr[name_offset:name_offset + name_length * 2].decode("utf-16le") if name_length else ""
                            info = {"stream_name": stream_name, "resident": not bool(attr[8]), "attribute_offset": attr_position,
                                    "attribute_id": struct.unpack_from("<H", attr, 14)[0]}
                            entry["streams"].append(info)
                            if attr[8]:
                                counts["nonresident_streams"] += 1
                                info.update(status="unsupported_nonresident", reason="No validated logical-to-physical mapping", attribute_hex=attr.hex())
                                continue
                            size, start = struct.unpack_from("<IH", attr, 16)
                            if directory:
                                info["status"] = "skipped_directory_stream"
                                continue
                            if struct.unpack_from("<H", attr, 12)[0] & 0xC001:
                                info["status"] = "unsupported_attribute_flags"
                                continue
                            if counts["recovered_bytes"] + size > max_output_bytes:
                                info["status"] = "output_limit"
                                report["status"] = "output_limit"
                                continue
                            data = attr[start:start + size]
                            folder = "in_use" if flags & 1 else "deleted_records"
                            relative = Path(folder) / portable_basename(f"{offset}_{attr_position}_" + safe_name(name) + ("__stream_" + safe_name(stream_name) if stream_name else ""))
                            target = output / relative
                            created = False
                            try:
                                target.parent.mkdir(exist_ok=True)
                                with target.open("xb") as exported:
                                    created = True
                                    exported.write(data)
                                    exported.flush()
                                    os.fsync(exported.fileno())
                            except OSError as error:
                                counts["export_failures"] += 1
                                info.update(status="export_failed", error=f"{type(error).__name__}: {error}")
                                if created:
                                    try:
                                        target.unlink()
                                    except OSError:
                                        info["incomplete_output"] = relative.as_posix()
                                if error.errno in (errno.ENOSPC, errno.EDQUOT, errno.EIO):
                                    # Stop on storage-wide failures rather than fill the disk with retries.
                                    index.write(json.dumps(entry, ensure_ascii=True) + "\n")
                                    raise
                                continue
                            info.update(status="recovered", size=size, sha256=hashlib.sha256(data).hexdigest(), output=relative.as_posix())
                            report["files"].append({"offset": offset, "name": name, "file_names": links, "in_use": bool(flags & 1), **info})
                            counts["resident_streams"] += 1
                            counts["recovered_bytes"] += size
                    except (ValueError, EOFError, IndexError, KeyError, TypeError, struct.error) as error:
                        counts["invalid_records"] += 1
                        entry.update(status="invalid_record", error=str(error)[:200])
                    index.write(json.dumps(entry, ensure_ascii=True) + "\n")
                    index.flush()
                    if counts["aligned_candidates"] % 1000 == 0:
                        os.fsync(index.fileno())
                        durable_json(manifest, report)
                report["scanned_through_offset"] = min(position, limit)
                if report["status"] == "running":
                    report["status"] = "scan_limit" if limit < original.st_size else "completed_with_errors" if counts["export_failures"] else "completed"
            finally:
                index.flush()
                os.fsync(index.fileno())
    except KeyboardInterrupt:
        report["status"] = "cancelled"
    except Exception as error:
        report.update(status="failed", error=f"{type(error).__name__}: {error}")
        raise
    finally:
        try:
            unchanged = identity(original) == identity(source.stat())
        except OSError:
            unchanged = False
        report["source_size_and_mtime_unchanged"] = unchanged
        report["source_stat_unchanged"] = unchanged
        if not unchanged:
            report["status"] = "source_changed"
        durable_json(manifest, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--max-candidates", type=int, default=1000000)
    parser.add_argument("--max-output-bytes", type=int, default=1024 * 1024 * 1024)
    parser.add_argument("--max-scan-bytes", type=int)
    args = parser.parse_args()
    report = recover(args.source, args.output, max_candidates=args.max_candidates,
                     max_output_bytes=args.max_output_bytes, max_scan_bytes=args.max_scan_bytes)
    print(json.dumps({key: value for key, value in report.items() if key != "files"}, indent=2))
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
