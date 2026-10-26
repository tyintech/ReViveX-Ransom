"""Verify exported bytes against explicit salvage manifests, never execute payloads."""
import argparse
import hashlib
import json
import os
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath


def safe_output(root, relative):
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("Output must use a nonempty relative POSIX path")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or PureWindowsPath(relative).drive or any(part in ("..", ".", "") for part in relative.split("/")):
        raise ValueError("Unsafe output path")
    target = root / pure
    if any(item.is_symlink() for item in (target, *target.parents)):
        raise ValueError("Symlink outputs are not accepted")
    if not target.is_file():
        raise ValueError("Output is missing or not a regular file")
    return target


def digest_file(path):
    if not path.is_file():
        raise ValueError("Hash input must be a regular file")
    sha = hashlib.sha256()
    crc = size = 0
    with path.open("rb") as stream:
        original = os.fstat(stream.fileno())
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            sha.update(chunk)
            crc = zlib.crc32(chunk, crc)
        final = os.fstat(stream.fileno())
    if (original.st_size, original.st_mtime_ns) != (final.st_size, final.st_mtime_ns):
        raise ValueError("File changed during verification")
    return size, sha.hexdigest(), f"{crc & 0xffffffff:08x}"


def verify(root, manifests=None, source=None, report_path=None, max_manifest_bytes=64 * 1024 * 1024):
    """Root defaults to containing manifest(s); explicit paths avoid case-specific folders.

    Legacy relative-path manifests are accepted. Legacy absolute output paths are
    deliberately rejected; they must be migrated explicitly by their owner.
    """
    root = Path(root)
    if max_manifest_bytes <= 0:
        raise ValueError("Manifest size limit must be positive")
    paths = [Path(path) for path in manifests] if manifests is not None else [
        path for name in ("recovery_manifest.json", "_salvage_manifest.json", "carve_manifest.json", "manifest.json")
        if (path := root / name).is_file()]
    if not paths:
        raise ValueError("No supported manifests found; pass --manifest explicitly")
    report = {"schema": "revivex.salvage-verification", "schema_version": 1,
              "status": "completed", "verified_outputs": 0, "verification_failures": [],
              "manifests": [], "source_verification": "not_requested",
              "limitations": ["Verifies exported-byte integrity against manifests, not original content authenticity.",
                              "Does not establish decryption, complete files, original directory paths, or VHDX repair.",
                              "No recovered payload is executed."]}
    expected_source_hashes = set()
    for manifest in paths:
        summary = {"manifest": str(manifest), "verified_outputs": 0}
        report["manifests"].append(summary)
        try:
            if manifest.stat().st_size > max_manifest_bytes:
                raise ValueError("Manifest exceeds configured size limit")
            content = json.loads(manifest.read_text(encoding="utf-8"))
            if not isinstance(content, dict):
                raise ValueError("Manifest must be a JSON object")
            if content.get("schema_version", 1) != 1:
                raise ValueError("Unsupported schema version")
            entries = content.get("files", content.get("records"))
            if not isinstance(entries, list):
                raise ValueError("Manifest has no files or records list")
            source_hash = content.get("input_sha256") or content.get("source_sha256")
            if source_hash:
                expected_source_hashes.add(source_hash)
            summary["scan_status"] = content.get("status", "legacy_unspecified")
            for index, entry in enumerate(entries):
                if isinstance(entry, dict) and entry.get("status") not in (None, "recovered"):
                    continue
                try:
                    if not isinstance(entry, dict):
                        raise ValueError("File entry must be an object")
                    path = safe_output(manifest.parent, entry["output"])
                    size, sha, crc = digest_file(path)
                    if size != entry["size"] or sha != entry["sha256"]:
                        raise ValueError("Size or SHA-256 mismatch")
                    if "crc32" in entry and crc != entry["crc32"].lower():
                        raise ValueError("CRC-32 mismatch")
                    summary["verified_outputs"] += 1
                    report["verified_outputs"] += 1
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                    report["verification_failures"].append({"manifest": str(manifest), "entry": index, "error": str(error)})
        except (OSError, ValueError, TypeError) as error:
            report["verification_failures"].append({"manifest": str(manifest), "error": str(error)})
    if source is not None:
        try:
            size, sha, _ = digest_file(Path(source))
            report.update(source_size=size, source_sha256=sha)
            report["source_verification"] = "no_reference_hash" if not expected_source_hashes else "matched" if expected_source_hashes == {sha} else "mismatch"
            if report["source_verification"] == "mismatch":
                report["verification_failures"].append({"error": "Source hash does not match all manifest reference hashes"})
        except (OSError, ValueError) as error:
            report["source_verification"] = "failed"
            report["verification_failures"].append({"error": str(error)})
    if report["verification_failures"]:
        report["status"] = "failed"
    if report_path is not None:
        with Path(report_path).open("x", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Directory containing default manifests")
    parser.add_argument("--manifest", type=Path, action="append", help="Explicit manifest; repeat as needed")
    parser.add_argument("--source", type=Path, help="Optionally hash source and compare available manifest hashes")
    parser.add_argument("--report", type=Path, help="New output report path (never overwritten)")
    parser.add_argument("--max-manifest-bytes", type=int, default=64 * 1024 * 1024)
    args = parser.parse_args()
    report = verify(args.root, args.manifest, args.source, args.report, args.max_manifest_bytes)
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 1 if report["status"] == "failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
