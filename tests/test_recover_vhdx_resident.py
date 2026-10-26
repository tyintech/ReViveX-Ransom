import struct
import tempfile
import unittest
from pathlib import Path

from recover_vhdx_resident import parse_record, recover


def resident_attribute(attr_type, value):
    length = (24 + len(value) + 7) // 8 * 8
    attribute = bytearray(length)
    struct.pack_into("<II", attribute, 0, attr_type, length)
    struct.pack_into("<IH", attribute, 16, len(value), 24)
    attribute[24:24 + len(value)] = value
    return attribute


def make_record():
    record = bytearray(1024)
    record[:4] = b"FILE"
    struct.pack_into("<HH", record, 4, 48, 3)
    filename = "example.txt".encode("utf-16le")
    value = bytearray(66 + len(filename))
    value[64] = len(filename) // 2
    value[65] = 1
    value[66:] = filename
    attributes = resident_attribute(0x30, value) + resident_attribute(0x80, b"verified test data") + b"\xff\xff\xff\xff"
    struct.pack_into("<HHII", record, 20, 56, 1, 56 + len(attributes), 1024)
    struct.pack_into("<I", record, 44, 42)
    record[56:56 + len(attributes)] = attributes
    record[48:54] = b"\x12\x34\x00\x00\x00\x00"
    record[510:512] = record[1022:1024] = b"\x12\x34"
    return bytes(record)


class RecoveryTests(unittest.TestCase):
    def test_valid_record(self):
        record, flags = parse_record(make_record())
        self.assertEqual(record.filename, "example.txt")
        self.assertEqual(flags, 1)
        self.assertEqual(record.open().read(), b"verified test data")

    def test_corrupt_fixup_rejected(self):
        raw = bytearray(make_record())
        raw[510] ^= 1
        with self.assertRaises(ValueError):
            parse_record(raw)

    def test_extract_without_changing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "sample.bin"
            original = b"\x00" * 512 + make_record()
            source.write_bytes(original)
            output = Path(directory) / "recovered"
            result = recover(source, output)
            self.assertEqual(result["counts"]["resident_streams"], 1)
            self.assertEqual(result["files"][0]["name"], "example.txt")
            self.assertEqual(result["files"][0]["stream_name"], "")
            self.assertEqual((output / result["files"][0]["output"]).read_bytes(), b"verified test data")
            self.assertEqual(source.read_bytes(), original)
            with self.assertRaises(ValueError):
                recover(source, output)


if __name__ == "__main__":
    unittest.main()

def record_with_attributes(attributes, flags=1):
    raw = bytearray(make_record())
    raw[56:] = bytes(968)
    data = b"".join(attributes) + b"\xff\xff\xff\xff"
    if len(data) > 966:
        raise ValueError("Test record too large")
    raw[56:56 + len(data)] = data
    struct.pack_into("<HHII", raw, 20, 56, flags, 56 + len(data), 1024)
    # Preserve actual sector tails in the update sequence array.
    raw[50:52], raw[52:54] = raw[510:512], raw[1022:1024]
    raw[510:512] = raw[1022:1024] = raw[48:50]
    return bytes(raw)


def filename_attribute(name, namespace=1, parent=7, sequence=3):
    encoded = name.encode("utf-16le")
    value = bytearray(66 + len(encoded))
    struct.pack_into("<Q", value, 0, parent | sequence << 48)
    value[64:66] = bytes((len(encoded) // 2, namespace))
    value[66:] = encoded
    return resident_attribute(0x30, value)


class EvidenceTests(unittest.TestCase):
    def recover_fixture(self, raw, **options):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        source = root / "input.bin"
        source.write_bytes(raw)
        output = root / "output"
        report = recover(source, output, **options)
        import json
        records = [json.loads(line) for line in (output / "record_index.jsonl").read_text().splitlines()]
        return report, records, output

    def test_all_links_preserved_and_export_deterministic(self):
        attrs = [filename_attribute("SHORT.TXT", 2), filename_attribute("long name.txt", 1, 9, 4),
                 filename_attribute("another.txt", 1, 10, 5), resident_attribute(0x80, b"data")]
        report, records, output = self.recover_fixture(record_with_attributes(attrs))
        self.assertEqual(len(records[0]["file_names"]), 3)
        self.assertEqual(records[0]["name"], "another.txt")
        self.assertEqual(records[0]["file_names"][1]["parent_sequence"], 4)
        self.assertFalse(report["capabilities"]["vhdx_mapping_validated"])
        self.assertEqual(report["schema_version"], 1)
        self.assertTrue((output / report["files"][0]["output"]).is_file())

    def test_nameless_and_colliding_streams_are_exported(self):
        raw = record_with_attributes([resident_attribute(0x80, b"one"), resident_attribute(0x80, b"two")])
        report, records, _ = self.recover_fixture(raw)
        self.assertEqual(len(report["files"]), 2)
        self.assertEqual(records[0]["file_names"], [])
        self.assertNotEqual(report["files"][0]["output"], report["files"][1]["output"])

    def test_nonresident_is_explicit(self):
        attr = bytearray(64)
        struct.pack_into("<II", attr, 0, 0x80, 64)
        attr[8] = 1
        report, records, _ = self.recover_fixture(record_with_attributes([attr]))
        self.assertEqual(report["counts"]["nonresident_streams"], 1)
        self.assertEqual(records[0]["streams"][0]["status"], "unsupported_nonresident")
        self.assertEqual(report["files"], [])

    def test_corrupt_record_is_indexed(self):
        raw = bytearray(make_record())
        raw[510] ^= 1
        report, records, _ = self.recover_fixture(raw)
        self.assertEqual(report["counts"]["invalid_records"], 1)
        self.assertEqual(records[0]["status"], "invalid_record")

    def test_limits_and_cancel_are_reported(self):
        report, _, _ = self.recover_fixture(make_record(), max_output_bytes=0)
        self.assertEqual(report["status"], "output_limit")
        report, _, _ = self.recover_fixture(make_record() * 2, max_candidates=1)
        self.assertEqual(report["status"], "candidate_limit")
        report, _, _ = self.recover_fixture(make_record(), max_scan_bytes=100)
        self.assertEqual(report["status"], "scan_limit")
        report, _, output = self.recover_fixture(make_record(), cancelled=lambda: True)
        self.assertEqual(report["status"], "cancelled")
        self.assertTrue((output / "recovery_manifest.json").is_file())

    def test_empty_source(self):
        report, records, _ = self.recover_fixture(b"")
        self.assertEqual(report["status"], "completed")
        self.assertEqual(records, [])

    def test_unsafe_filename_sanitized(self):
        from recover_vhdx_resident import safe_name
        for name in ("CON", "LPT1.txt", "../unsafe\\name", "...", ""):
            value = safe_name(name)
            self.assertNotIn("/", value)
            self.assertNotIn("\\", value)
            self.assertNotIn(value, ("", ".", "..", "CON", "LPT1.txt"))

    def test_invalid_attribute_name_rejected(self):
        raw = bytearray(make_record())
        raw[65] = 255
        struct.pack_into("<H", raw, 66, 1000)
        with self.assertRaises(ValueError):
            parse_record(raw)

    def test_complete_export_name_has_portable_byte_budget(self):
        raw = record_with_attributes([filename_attribute("测" * 100), resident_attribute(0x80, b"unicode")])
        report, records, output = self.recover_fixture(raw)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(records[0]["name"], "测" * 100)
        path = Path(report["files"][0]["output"])
        self.assertLessEqual(len(path.name.encode("utf-8")), 240)
        self.assertEqual((output / path).read_bytes(), b"unicode")

    def test_export_failure_does_not_drop_later_records(self):
        from unittest.mock import patch
        real_open = Path.open
        def fail_one(path, mode="r", *args, **kwargs):
            if mode == "xb" and path.name.startswith("0_"):
                raise PermissionError("Synthetic individual export failure")
            return real_open(path, mode, *args, **kwargs)
        with patch.object(Path, "open", fail_one):
            report, records, _ = self.recover_fixture(make_record() * 2)
        self.assertEqual(report["status"], "completed_with_errors")
        self.assertEqual(report["counts"]["export_failures"], 1)
        self.assertEqual(report["counts"]["resident_streams"], 1)
        self.assertEqual(records[0]["streams"][0]["status"], "export_failed")
        self.assertEqual(records[1]["streams"][0]["status"], "recovered")
