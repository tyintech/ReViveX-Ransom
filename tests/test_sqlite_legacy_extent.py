"""Legacy SQLite sizes need an explicit file boundary and independent integrity."""
import contextlib
import hashlib
import io
import json
import sqlite3
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from carve_verified_formats import carve, main, sqlite_extent, verify_outputs


LIMIT = 1048576


def database_bytes(root, page_size=4096):
    path = root / "original.sqlite"
    with contextlib.closing(sqlite3.connect(path)) as database:
        database.execute(f"PRAGMA page_size={page_size}")
        database.execute("CREATE TABLE example (value TEXT)")
        database.execute("INSERT INTO example VALUES ('intact legacy record')")
        database.commit()
    return path.read_bytes()


def legacy_header(data, stale=False):
    result = bytearray(data)
    result[28:32] = struct.pack(">I", 1 if stale else 0)
    if stale:
        # The old count is intentionally too small. SQLite itself ignores it
        # because the change counter and version-valid-for number differ.
        result[92:96] = struct.pack(">I", struct.unpack_from(">I", data, 24)[0] ^ 1)
    return bytes(result)


def run_carve(source, output, *, standalone=True, max_file=LIMIT, max_total=LIMIT):
    with contextlib.redirect_stdout(io.StringIO()):
        return carve(source, output, max_file, max_total, LIMIT, standalone_sqlite=standalone)


class SQLiteLegacyExtentTests(unittest.TestCase):
    def test_zero_and_stale_counts_need_explicit_standalone_extent(self):
        with tempfile.TemporaryDirectory() as directory:
            data = database_bytes(Path(directory))
            for stale in (False, True):
                with self.subTest(stale=stale):
                    legacy = legacy_header(data, stale)
                    with self.assertRaisesRegex(ValueError, "page count is absent or stale"):
                        sqlite_extent(legacy, 0, len(legacy))
                    end, details = sqlite_extent(legacy, 0, len(legacy), standalone=True)
                    self.assertEqual(end, len(legacy))
                    self.assertEqual(details["page_count"], len(legacy) // 4096)
                    self.assertEqual(details["header_page_count"], int(stale))
                    self.assertFalse(details["header_page_count_valid"])
                    self.assertEqual(details["extent_source"], "explicit_standalone_file_boundary")

    def test_carve_and_reverify_preserve_complete_source_and_provenance(self):
        for stale in (False, True):
            with self.subTest(stale=stale), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = legacy_header(database_bytes(root), stale)
                source = root / "source.sqlite"
                source.write_bytes(data)
                original = source.stat()
                output = root / "output"
                report = run_carve(source, output)
                self.assertEqual(report["counts"], {"sqlite_candidates": 1, "sqlite_unique_outputs": 1})
                self.assertEqual(report["sqlite_boundary_mode"], "explicit_standalone_file")
                self.assertEqual(report["source_size"], len(data))
                self.assertEqual(report["source_sha256"], hashlib.sha256(data).hexdigest())
                self.assertTrue(report["source_size_and_mtime_unchanged"])
                record, = report["files"]
                self.assertEqual(record["integrity_check"], "ok")
                self.assertEqual(record["provenance"], "source_bytes_only_not_original_verified")
                self.assertEqual(record["offset"], 0)
                self.assertFalse(Path(record["output"]).is_absolute())
                self.assertEqual((output / record["output"]).read_bytes(), data)
                self.assertEqual(source.read_bytes(), data)
                self.assertEqual(source.stat().st_mtime_ns, original.st_mtime_ns)
                self.assertFalse(list(output.glob("candidate_*")))
                verified = verify_outputs(output, report["source_sha256"])
                self.assertEqual(verified["verified_unique_files"], {"sqlite": 1})
                with contextlib.closing(sqlite3.connect(
                    (output / record["output"]).resolve().as_uri() + "?mode=ro&immutable=1", uri=True,
                )) as database:
                    self.assertEqual(database.execute("SELECT value FROM example").fetchall(),
                                     [("intact legacy record",)])
                self.assertFalse(list(output.glob("*-wal")))
                self.assertFalse(list(output.glob("*-journal")))

    def test_default_raw_scan_does_not_trust_eof_even_at_offset_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = legacy_header(database_bytes(root))
            for index, payload in enumerate((data, b"prefix" + data, data + b"suffix")):
                with self.subTest(index=index):
                    source = root / f"source-{index}.bin"
                    source.write_bytes(payload)
                    report = run_carve(source, root / f"output-{index}", standalone=False)
                    self.assertEqual(report["files"], [])
                    self.assertEqual(report["counts"]["sqlite_rejected"], 1)
                    self.assertIn("sqlite: SQLite header page count is absent or stale", report["rejection_reasons"])

    def test_standalone_mode_does_not_search_for_an_embedded_database(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.bin"
            source.write_bytes(b"prefix" + legacy_header(database_bytes(root)))
            report = run_carve(source, root / "output")
            self.assertEqual(report["files"], [])
            self.assertEqual(report["counts"], {"sqlite_candidates": 1, "sqlite_rejected": 1})
            self.assertIn("sqlite: Invalid SQLite header", report["rejection_reasons"])

    def test_standalone_mode_does_not_scan_database_blob_contents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = database_bytes(root)
            source = root / "source.sqlite"
            with contextlib.closing(sqlite3.connect(source)) as database:
                database.execute("CREATE TABLE attachments (content BLOB)")
                database.execute("INSERT INTO attachments VALUES (?)", (data,))
                database.commit()
            source.write_bytes(legacy_header(source.read_bytes()))
            report = run_carve(source, root / "output")
            self.assertEqual(report["counts"], {"sqlite_candidates": 1, "sqlite_unique_outputs": 1})

    def test_integrity_and_alignment_reject_damaged_or_padded_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = legacy_header(database_bytes(root))
            variants = {
                "broken_btree": data[:100] + b"\xff" + data[101:],
                "truncated_page": data[:-4096],
                "extra_page": data + bytes(4096),
                "extra_byte": data + b"\x00",
                "partial_page": data[:-1],
            }
            for label, payload in variants.items():
                with self.subTest(label=label):
                    source = root / f"{label}.sqlite"
                    source.write_bytes(payload)
                    output = root / label
                    report = run_carve(source, output)
                    self.assertEqual(report["files"], [])
                    self.assertEqual(report["counts"]["sqlite_rejected"], 1)
                    self.assertFalse(list(output.glob("*.sqlite")))
                    self.assertEqual(source.read_bytes(), payload)

    def test_size_limits_cannot_be_used_as_fallback_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = legacy_header(database_bytes(root))
            source = root / "source.sqlite"
            source.write_bytes(data)
            for label, limits in (("file", {"max_file": len(data) - 1}),
                                  ("total", {"max_total": len(data) - 1})):
                with self.subTest(limit=label):
                    output = root / label
                    report = run_carve(source, output, **limits)
                    self.assertEqual(report["files"], [])
                    self.assertEqual(report["counts"]["sqlite_rejected"], 1)
                    self.assertFalse(list(output.glob("*.sqlite")))
            with self.assertRaisesRegex(ValueError, "full source boundary"):
                sqlite_extent(data, 0, len(data) - 4096, standalone=True)
            with self.assertRaisesRegex(ValueError, "full source boundary"):
                sqlite_extent(b"prefix" + data, 6, 6 + len(data), standalone=True)

    def test_current_header_count_never_gets_overridden(self):
        with tempfile.TemporaryDirectory() as directory:
            data = database_bytes(Path(directory))
            end, details = sqlite_extent(data, 0, len(data), standalone=True)
            self.assertEqual(end, len(data))
            self.assertTrue(details["header_page_count_valid"])
            self.assertEqual(details["extent_source"], "header_page_count")
            for pages in (1, 100):
                with self.subTest(pages=pages):
                    damaged = bytearray(data)
                    damaged[28:32] = struct.pack(">I", pages)
                    with self.assertRaises(ValueError):
                        sqlite_extent(damaged, 0, len(damaged), standalone=True)
            with self.assertRaises(ValueError):
                sqlite_extent(data + bytes(4096), 0, len(data) + 4096, standalone=True)

    def test_smallest_and_largest_page_sizes(self):
        for page_size in (512, 65536):
            with self.subTest(page_size=page_size), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source.sqlite"
                source.write_bytes(legacy_header(database_bytes(root, page_size)))
                report = run_carve(source, root / "output")
                self.assertEqual(report["counts"]["sqlite_unique_outputs"], 1)
                self.assertEqual(report["files"][0]["page_size"], page_size)

    def test_fallback_verification_requires_consistent_boundary_evidence(self):
        cases = (
            ("sqlite_boundary_mode", "header_page_count_only", False),
            ("source_size", 0, False),
            ("source_sha256", "0" * 64, False),
            ("offset", 1, True),
            ("header_page_count_valid", True, True),
            ("page_count", 99, True),
            ("extent_source", "header_page_count", True),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite"
            source.write_bytes(legacy_header(database_bytes(root)))
            for index, (key, value, in_record) in enumerate(cases):
                with self.subTest(field=key):
                    output = root / str(index)
                    report = run_carve(source, output)
                    (report["files"][0] if in_record else report)[key] = value
                    (output / "manifest.json").write_text(json.dumps(report))
                    with self.assertRaisesRegex(ValueError, "Output verification failed"):
                        verify_outputs(output, report["source_sha256"])

    def test_current_header_outputs_still_reverify_in_standalone_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite"
            source.write_bytes(database_bytes(root))
            output = root / "output"
            report = run_carve(source, output)
            self.assertEqual(report["files"][0]["extent_source"], "header_page_count")
            verified = verify_outputs(output, report["source_sha256"])
            self.assertEqual(verified["verified_unique_files"], {"sqlite": 1})

    def test_invalid_input_extents_raise_value_error(self):
        for start, limit in ((-1, 100), (0, 101), (1, 0), (0, 0)):
            with self.subTest(start=start, limit=limit), self.assertRaises(ValueError):
                sqlite_extent(bytes(100), start, limit)

    def test_standalone_mode_rejects_gentlemen_inference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "cannot use inferred Gentlemen boundaries"):
                carve(root / "source", root / "output", LIMIT, LIMIT, LIMIT,
                      gentlemen=True, standalone_sqlite=True)
            self.assertFalse((root / "output").exists())

    def test_cli_exposes_explicit_standalone_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.sqlite"
            source.write_bytes(legacy_header(database_bytes(root)))
            output = root / "output"
            with patch("sys.argv", ["carve_verified_formats", str(source), str(output), "--standalone-sqlite"]), \
                    contextlib.redirect_stdout(io.StringIO()):
                main()
            report = json.loads((output / "manifest.json").read_text())
            self.assertEqual(report["counts"]["sqlite_unique_outputs"], 1)
            with patch("sys.argv", ["carve_verified_formats", str(source), str(root / "bad"),
                                    "--standalone-sqlite", "--gentlemen"]), \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                main()
            self.assertEqual(failure.exception.code, 2)
            self.assertFalse((root / "bad").exists())


if __name__ == "__main__":
    unittest.main()
