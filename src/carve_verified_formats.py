import argparse
import hashlib
import json
import sqlite3
import struct
import zlib
from collections import Counter
from contextlib import closing
from pathlib import Path

from analyze_gentlemen_pairs import footer, geometry
from revivex_source_io import BoundedSource, unpack_at

FULL_HASH_LIMIT = 4 * 1024 ** 3


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SQLITE_SIGNATURE = b"SQLite format 3\x00"
PNG_DEPTHS = {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}
PNG_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


def png_rows(width, height, bits, interlaced):
    passes = [(0, 0, 1, 1)] if not interlaced else [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2),
    ]
    rows = []
    for x, y, dx, dy in passes:
        columns = max(0, (width - x + dx - 1) // dx)
        count = max(0, (height - y + dy - 1) // dy)
        if columns and count:
            rows.append(((columns * bits + 7) // 8 + 1, count))
    return rows


def validate_palette_pixels(raw, width, height, depth, interlace, entries):
    """Reverse PNG filters per Adam7 pass and validate real pixels, not padding."""
    passes = [(0, 0, 1, 1)] if not interlace else [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2),
    ]
    cursor = 0
    for x, y, dx, dy in passes:
        columns = max(0, (width - x + dx - 1) // dx)
        count = max(0, (height - y + dy - 1) // dy)
        if not columns or not count:
            continue
        row_bytes = (columns * depth + 7) // 8
        previous = bytearray(row_bytes)
        for _ in range(count):
            filtering = raw[cursor]
            row = bytearray(raw[cursor + 1:cursor + 1 + row_bytes])
            cursor += row_bytes + 1
            for i in range(row_bytes):
                left = row[i - 1] if i else 0
                up = previous[i]
                corner = previous[i - 1] if i else 0
                if filtering == 1:
                    predictor = left
                elif filtering == 2:
                    predictor = up
                elif filtering == 3:
                    predictor = (left + up) // 2
                elif filtering == 4:
                    p = left + up - corner
                    distances = (abs(p - left), abs(p - up), abs(p - corner))
                    predictor = (left, up, corner)[distances.index(min(distances))]
                else:
                    predictor = 0
                row[i] = (row[i] + predictor) & 255
            for column in range(columns):
                bit = column * depth
                pixel = (row[bit // 8] >> (8 - depth - bit % 8)) & ((1 << depth) - 1)
                if pixel >= entries:
                    raise ValueError("PNG palette index out of range")
            previous = row


def parse_png(source, start, limit, max_decoded):
    if source[start:start + 8] != PNG_SIGNATURE:
        raise ValueError("Invalid PNG signature")
    if not 0 <= start < limit <= len(source) or max_decoded <= 0:
        raise ValueError("Invalid PNG input extent or decoded limit")
    position = start + 8
    dimensions = None
    palette = False
    idat_started = idat_ended = False
    decoder = zlib.decompressobj()
    raw = bytearray()
    palette_entries = 0
    chunks = 0
    while position + 12 <= limit:
        length = unpack_at(">I", source, position)[0]
        kind = source[position + 4:position + 8]
        end = position + 12 + length
        if end > limit or length > 0x7fffffff:
            raise ValueError("PNG chunk exceeds extent or size limit")
        if len(kind) != 4 or any(not (65 <= byte <= 90 or 97 <= byte <= 122) for byte in kind) or kind[2] & 32:
            raise ValueError("Invalid PNG chunk type")
        chunk = source[position + 8:end - 4]
        crc = zlib.crc32(chunk, zlib.crc32(kind))
        if crc != unpack_at(">I", source, end - 4)[0]:
            raise ValueError("PNG chunk CRC mismatch")
        if dimensions is None:
            if kind != b"IHDR" or length != 13:
                raise ValueError("PNG must start with a 13-byte IHDR")
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", chunk)
            if not 0 < width <= 0x7fffffff or not 0 < height <= 0x7fffffff or depth not in PNG_DEPTHS.get(color, ()):
                raise ValueError("Invalid PNG dimensions, depth or color type")
            if compression != 0 or filtering != 0 or interlace not in (0, 1):
                raise ValueError("Unsupported PNG image method")
            dimensions = width, height, depth, color, interlace
            rows = png_rows(width, height, depth * PNG_CHANNELS[color], interlace)
            expected = sum(size * count for size, count in rows)
            if expected > max_decoded:
                raise ValueError("PNG decoded image exceeds limit")
        elif kind == b"IHDR":
            raise ValueError("Repeated PNG IHDR")
        elif kind == b"PLTE":
            if palette or idat_started or color in (0, 4) or not length or length % 3 or length > 768:
                raise ValueError("Invalid PNG palette")
            if color == 3 and length // 3 > 1 << depth:
                raise ValueError("PNG palette exceeds bit depth")
            palette = True
            palette_entries = length // 3
        elif kind == b"IDAT":
            if idat_ended or color == 3 and not palette:
                raise ValueError("Invalid PNG IDAT ordering")
            # Consume compressed input in bounded pieces, without a joined IDAT copy.
            for offset in range(0, len(chunk), 65536):
                raw.extend(decoder.decompress(chunk[offset:offset + 65536], expected - len(raw) + 1))
                if len(raw) > expected or decoder.unused_data or decoder.unconsumed_tail:
                    raise ValueError("PNG image stream length or termination mismatch")
            idat_started = True
        elif kind == b"IEND":
            if length or not idat_started:
                raise ValueError("Invalid PNG IEND")
            if len(raw) != expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise ValueError("PNG image stream length or termination mismatch")
            cursor = 0
            for row_size, count in rows:
                for _ in range(count):
                    if raw[cursor] > 4:
                        raise ValueError("Invalid PNG row filter")
                    cursor += row_size
            if color == 3:
                validate_palette_pixels(raw, width, height, depth, interlace, palette_entries)
            return end, {
                "width": width, "height": height, "bit_depth": depth, "color_type": color,
                "interlaced": bool(interlace), "chunks_crc_verified": chunks + 1,
                "decoded_scanline_bytes": expected,
                "palette_indices_verified": color == 3,
            }
        elif not kind[0] & 32:
            raise ValueError("Unknown critical PNG chunk")
        if kind != b"IDAT" and idat_started:
            idat_ended = True
        chunks += 1
        position = end
    raise ValueError("PNG lacks complete IEND within extent")


def sqlite_extent(source, start, limit, *, standalone=False):
    """Find a candidate extent; callers must still run ``verify_sqlite``.

    Raw carving requires a current in-header page count. ``standalone=True``
    explicitly asserts that the entire input is one complete database file,
    so its physical boundary can supply an absent or obsolete page count.
    A scan limit, encrypted-interval boundary, or embedded signature is never
    sufficient evidence for that fallback.
    """
    if not 0 <= start < limit <= len(source):
        raise ValueError("Invalid SQLite input extent")
    if standalone and (start != 0 or limit != len(source)):
        raise ValueError("Standalone SQLite requires the full source boundary within the size limit")
    if start + 100 > limit or source[start:start + 16] != SQLITE_SIGNATURE:
        raise ValueError("Invalid SQLite header")
    header = source[start:start + 100]
    encoded_size = struct.unpack_from(">H", header, 16)[0]
    page_size = 65536 if encoded_size == 1 else encoded_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ValueError("Invalid SQLite page size")
    if header[18] not in (1, 2) or header[19] not in (1, 2) or header[21:24] != b"\x40\x20\x20":
        raise ValueError("Invalid SQLite format parameters")
    if page_size - header[20] < 480 or any(header[72:92]):
        raise ValueError("Invalid SQLite reserved header fields")
    header_pages = unpack_at(">I", header, 28)[0]
    header_count_valid = bool(header_pages and header[24:28] == header[92:96])
    pages = header_pages
    extent_source = "header_page_count"
    if not header_count_valid:
        if not standalone:
            raise ValueError("SQLite header page count is absent or stale")
        if len(source) % page_size:
            raise ValueError("Standalone SQLite file is not an exact number of pages")
        pages = len(source) // page_size
        extent_source = "explicit_standalone_file_boundary"
    if not 0 < pages <= 0xfffffffe:
        raise ValueError("Invalid SQLite page count")
    schema_format = struct.unpack_from(">I", header, 44)[0]
    encoding = struct.unpack_from(">I", header, 56)[0]
    if schema_format not in (0, 1, 2, 3, 4) or encoding not in (0, 1, 2, 3):
        raise ValueError("Invalid SQLite schema format or encoding")
    end = start + page_size * pages
    if end > limit:
        raise ValueError("SQLite extent exceeds contiguous bytes or size limit")
    if standalone and end != len(source):
        raise ValueError("Standalone SQLite file size differs from current header extent")
    return end, {
        "page_size": page_size, "page_count": pages, "wal_mode": header[18] == 2,
        "extent_source": extent_source, "header_page_count": header_pages,
        "header_page_count_valid": header_count_valid,
    }


def verify_sqlite(path, max_progress_calls=5000):
    calls = 0

    def progress():
        nonlocal calls
        calls += 1
        return calls > max_progress_calls

    uri = path.resolve().as_uri() + "?mode=ro&immutable=1"
    with closing(sqlite3.connect(uri, uri=True)) as database:
        database.execute("PRAGMA trusted_schema=OFF")
        database.execute("PRAGMA query_only=ON")
        database.set_progress_handler(progress, 1000)
        result = database.execute("PRAGMA integrity_check").fetchall()
        if result != [("ok",)]:
            raise ValueError(f"SQLite integrity_check failed: {result[:3]}")
        return {"integrity_check": "ok", "schema_object_count": database.execute("SELECT count(*) FROM sqlite_schema").fetchone()[0]}


def carve(source, output, max_file, max_total, max_decoded, gentlemen=False, *, standalone_sqlite=False):
    if standalone_sqlite and gentlemen:
        raise ValueError("Standalone SQLite mode cannot use inferred Gentlemen boundaries")
    if output.exists():
        raise ValueError("Output directory must not already exist")
    if any(path.is_symlink() for path in [output, *output.parents]):
        raise ValueError("Symlink output paths forbidden")
    if min(max_file, max_total, max_decoded) <= 0 or source.stat().st_size == 0:
        raise ValueError("Positive limits and nonempty input required")
    original = source.stat()
    end_of_input = original.st_size
    excluded = []
    if gentlemen:
        info = footer(source)
        end_of_input = info["body_size"]
        excluded = geometry(end_of_input, info["mode"])
    output.mkdir(parents=True)
    counts = Counter()
    errors = Counter()
    contents = {}
    recovered = []
    total = 0
    with BoundedSource(source) as image:
        with (output / "candidates.jsonl").open("x", encoding="utf-8") as index:
            formats = (("sqlite", SQLITE_SIGNATURE),) if standalone_sqlite else (
                ("png", PNG_SIGNATURE), ("sqlite", SQLITE_SIGNATURE),
            )
            for name, signature in formats:
                position = 0
                while True:
                    # In standalone mode there is exactly one candidate, at
                    # offset zero. Never infer the end of an embedded database.
                    if standalone_sqlite:
                        if position:
                            break
                        start = 0
                    else:
                        start = image.find(signature, position, end_of_input)
                    if start < 0:
                        break
                    position = start + len(signature)
                    counts[name + "_candidates"] += 1
                    candidate = {"format": name, "offset": start, "status": "rejected"}
                    limit = min(end_of_input, start + max_file)
                    temp = None
                    try:
                        for left, right in excluded:
                            if left <= start < right:
                                raise ValueError("Signature inside inferred encrypted interval")
                            if left > start:
                                limit = min(limit, left)
                        if name == "png":
                            end, details = parse_png(image, start, limit, max_decoded)
                        else:
                            end, details = sqlite_extent(image, start, limit, standalone=standalone_sqlite)
                        data = image[start:end]
                        digest = hashlib.sha256(data).hexdigest()
                        if name == "sqlite":
                            temp = output / f"candidate_{start}.sqlite"
                            with temp.open("xb") as target:
                                target.write(data)
                            details.update(verify_sqlite(temp))
                        key = (name, digest)
                        if key in contents:
                            candidate.update(status="verified_duplicate", sha256=digest, size=len(data), output=contents[key])
                            counts[name + "_verified_duplicates"] += 1
                        else:
                            if total + len(data) > max_total:
                                raise ValueError("Total output byte limit exceeded")
                            destination = output / f"{start}.{name}"
                            if temp is not None:
                                temp.rename(destination)
                                temp = None
                            else:
                                with destination.open("xb") as target:
                                    target.write(data)
                            contents[key] = destination.relative_to(output).as_posix()
                            total += len(data)
                            candidate.update(status="recovered", provenance="source_bytes_only_not_original_verified", sha256=digest, size=len(data), output=destination.relative_to(output).as_posix(), **details)
                            recovered.append(candidate.copy())
                            counts[name + "_unique_outputs"] += 1
                    except (ValueError, OSError, zlib.error, sqlite3.DatabaseError) as error:
                        candidate["error"] = str(error)
                        counts[name + "_rejected"] += 1
                        errors[name + ": " + str(error).split(":")[0]] += 1
                    finally:
                        if temp is not None:
                            temp.unlink()
                    index.write(json.dumps(candidate, ensure_ascii=True) + "\n")
            if len(image) <= FULL_HASH_LIMIT:
                source_digest = hashlib.sha256()
                for start in range(0, len(image), 8 * 1024 * 1024):
                    source_digest.update(image[start:start + 8 * 1024 * 1024])
                source_sha256, hash_status = source_digest.hexdigest(), "computed_full_source"
            else:
                source_sha256, hash_status = None, "skipped_large_source_stat_identity_only"
    final = source.stat()
    unchanged = (original.st_size, original.st_mtime_ns) == (final.st_size, final.st_mtime_ns)
    report = {
        "schema": "revivex.format-carving", "schema_version": 1,
        "status": "validated_format_carving_not_decryption_not_bootable_vhdx",
        "source": str(source), "source_sha256": source_sha256, "source_hash_status": hash_status,
        "source_size": original.st_size,
        "sqlite_boundary_mode": "explicit_standalone_file" if standalone_sqlite else "header_page_count_only",
        "source_size_and_mtime_unchanged": unchanged,
        "inferred_encrypted_intervals_excluded": excluded,
        "counts": dict(counts), "rejection_reasons": dict(errors),
        "unique_output_bytes": total, "files": recovered,
        "limitations": [
            "Only contiguous complete formats are recovered; fragmented files are rejected.",
            "PNG chunk CRC, zlib termination, decoded size, scanline filters and palette indices are checked; no original checksum exists.",
            "SQLite integrity_check verifies the standalone main database, not missing WAL transactions or application completeness.",
            "Absent or stale SQLite header page counts require explicit standalone-file mode and a complete page-aligned source boundary.",
            "Original filenames and directories are unknown; duplicate content is saved once.",
            "No decryption key or repaired/bootable VHDX is produced. Scan outputs for malware before use.",
        ],
    }
    with (output / "manifest.json").open("x", encoding="utf-8") as manifest:
        json.dump(report, manifest, ensure_ascii=True, indent=2)
    print(json.dumps({key: value for key, value in report.items() if key != "files"}, ensure_ascii=True, indent=2))
    if not unchanged:
        raise RuntimeError("Source size or modification time changed during carving")
    return report


def verify_outputs(output, expected_source_hash):
    report = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    failures = []
    counts = Counter()
    total = 0
    hash_comparable = report["source_sha256"] is not None and expected_source_hash is not None
    if hash_comparable and report["source_sha256"] != expected_source_hash:
        failures.append({"error": "Source hash does not match prior scan"})
    if not hash_comparable and expected_source_hash is not None and report["source_sha256"] is None and \
            report.get("source_hash_status") != "skipped_large_source_stat_identity_only":
        failures.append({"error": "Manifest lacks a source hash without a recorded large-source skip"})
    if report.get("source_size_and_mtime_unchanged") is not True:
        failures.append({"error": "Source stability was not confirmed during carving"})
    if report.get("status") != "validated_format_carving_not_decryption_not_bootable_vhdx":
        failures.append({"error": "Unsupported manifest provenance status"})
    for record in report["files"]:
        path = output / record["output"]
        try:
            if Path(record["output"]).is_absolute():
                raise ValueError("Manifest output must be relative")
            if record.get("status") != "recovered" or record.get("provenance") != "source_bytes_only_not_original_verified":
                raise ValueError("Manifest record lacks supported recovery provenance")
            if not path.resolve().is_relative_to(output.resolve()) or any(item.is_symlink() for item in (path, *path.parents)):
                raise ValueError("Manifest output path escapes recovery directory")
            data = path.read_bytes()
            if len(data) != record["size"] or hashlib.sha256(data).hexdigest() != record["sha256"]:
                raise ValueError("Output size or SHA-256 mismatch")
            if record["format"] == "png":
                end, _ = parse_png(data, 0, len(data), 128 * 1048576)
                if end != len(data):
                    raise ValueError("Trailing bytes after PNG IEND")
            elif record["format"] == "sqlite":
                standalone = record.get("extent_source") == "explicit_standalone_file_boundary"
                if standalone and (
                    report.get("sqlite_boundary_mode") != "explicit_standalone_file"
                    or record.get("offset") != 0
                    or report.get("source_size") != len(data)
                    or record.get("sha256") != report.get("source_sha256")
                ):
                    raise ValueError("SQLite fallback lacks explicit full-source boundary provenance")
                end, details = sqlite_extent(data, 0, len(data), standalone=standalone)
                if end != len(data):
                    raise ValueError("SQLite file size differs from header extent")
                if standalone and any(record.get(key) != value for key, value in details.items()):
                    raise ValueError("SQLite fallback extent evidence differs from output")
                verify_sqlite(path)
            else:
                raise ValueError("Unsupported output format")
            counts[record["format"]] += 1
            total += len(data)
        except (ValueError, OSError, zlib.error, sqlite3.DatabaseError) as error:
            failures.append({"output": str(path), "error": str(error)})
    if total != report["unique_output_bytes"]:
        failures.append({"error": "Verified output total differs from manifest"})
    verification = {
        "status": "verified_partial_carving" if not failures else "verification_failed",
        "source_sha256": report["source_sha256"],
        "source_hash_matches_previous_scan": (report["source_sha256"] == expected_source_hash) if hash_comparable else None,
        "source_hash_comparison": "compared" if hash_comparable else "not_possible_source_hash_not_computed_stat_identity_only",
        "verified_unique_files": dict(counts),
        "verified_output_bytes": total,
        "failures": failures,
        "warning": "These are format-validated outputs, not a decrypted or bootable VHDX.",
    }
    with (output / "verification.json").open("x", encoding="utf-8") as stream:
        json.dump(verification, stream, ensure_ascii=True, indent=2)
    if failures:
        raise ValueError(f"Output verification failed: {failures[:3]}")
    return verification


def main():
    parser = argparse.ArgumentParser(description="Read-only bounded PNG/SQLite carving with format validation")
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--max-file-mib", type=int, default=64)
    parser.add_argument("--max-total-mib", type=int, default=4096)
    parser.add_argument("--max-decoded-mib", type=int, default=128)
    parser.add_argument("--gentlemen", action="store_true", help="Exclude inferred encrypted chunks using the Gentlemen footer")
    parser.add_argument("--standalone-sqlite", action="store_true", help=(
        "Assert that the complete source is one standalone SQLite file; permits absent/stale "
        "header page counts only with exact page alignment and read-only integrity_check"
    ))
    args = parser.parse_args()
    if args.standalone_sqlite and args.gentlemen:
        parser.error("--standalone-sqlite cannot be combined with --gentlemen")
    carve(args.source, args.output, args.max_file_mib * 1048576, args.max_total_mib * 1048576,
          args.max_decoded_mib * 1048576, args.gentlemen, standalone_sqlite=args.standalone_sqlite)


if __name__ == "__main__":
    main()
