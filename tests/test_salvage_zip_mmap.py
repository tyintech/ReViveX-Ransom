import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


class MemoryMapTests(unittest.TestCase):
    def run_salvage(self, source_bytes, *options):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "disk.bin"
            source.write_bytes(source_bytes)
            output = root / "output"
            process = subprocess.run(
                [sys.executable, str(Path(__file__).resolve().parents[1] / "src" / "salvage_zip.py"),
                 str(source), str(output), "--memory-map", *options],
                capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads((output / "_salvage_manifest.json").read_text(encoding="utf-8"))
            for entry in report["records"]:
                if entry["status"] == "recovered":
                    data_root = root / "output_nested" if entry.get("output_root") == "nested" else output
                    data = (data_root / entry["output"]).read_bytes()
                    self.assertEqual(hashlib.sha256(data).hexdigest(), entry["sha256"])
            self.assertEqual(source.read_bytes(), source_bytes)
            return report

    def test_zip64_descriptors_and_preserved_duplicates(self):
        class Unseekable(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation()

        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            buffer = Unseekable()
            with zipfile.ZipFile(buffer, "w", method) as archive:
                with archive.open("same.txt", "w", force_zip64=True) as stream:
                    stream.write(b"payload PK\x07\x08 false descriptor" * 100)
            original = buffer.getvalue()
            report = self.run_salvage(original + original, "--preserve-duplicates")
            self.assertEqual(report["recovered_files"], 2)
            self.assertTrue(report["records"][1]["preserved_duplicate"])
            default = self.run_salvage(original + original)
            self.assertEqual(default["recovered_files"], 1)
            self.assertEqual(default["records"][1]["error"], "duplicate output path")

    def test_stored_descriptor_crc_failure_and_limit(self):
        from salvage_zip import stored_descriptor
        payload = b"stored content"
        broken = payload + b"PK\x07\x08" + struct.pack("<III", 1, len(payload), len(payload))
        with self.assertRaises(ValueError):
            stored_descriptor(broken, 0, len(payload))
        import zlib
        valid = payload + b"PK\x07\x08" + struct.pack("<IQQ", zlib.crc32(payload), len(payload), len(payload))
        with self.assertRaises(ValueError):
            stored_descriptor(valid, 0, len(payload) - 1, True)
        self.assertEqual(stored_descriptor(valid, 0, len(payload), True)[0], payload)

    def test_unsigned_zip64_descriptor(self):
        from salvage_zip import descriptor
        raw = struct.pack("<IQQ", 123, 42, 128)
        self.assertEqual(descriptor(raw, 0, 42, 128, True), (123, 42, 128))
        with self.assertRaises(ValueError):
            descriptor(raw[:16], 0, 42, 128, True)

    def test_zip64_size_fields(self):
        from salvage_zip import zip64_sizes
        extra = struct.pack("<HHQQ", 1, 16, 1234, 567)
        self.assertEqual(zip64_sizes(0xffffffff, 0xffffffff, extra), (567, 1234))
        with self.assertRaises(ValueError):
            zip64_sizes(0xffffffff, 0xffffffff, extra[:12])

    def test_identical_verified_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("document.txt", b"verified archive data" * 100)
                archive.writestr("../unsafe.txt", b"must not be extracted")
            source = root / "disk.bin"
            original = b"damaged disk prefix" + buffer.getvalue() + b"disk suffix"
            source.write_bytes(original)
            script = Path(__file__).resolve().parents[1] / "src" / "salvage_zip.py"
            summaries = []
            for mode in ([], ["--memory-map"]):
                output = root / ("mapped" if mode else "ordinary")
                process = subprocess.run([sys.executable, str(script), str(source), str(output), *mode], capture_output=True, text=True)
                self.assertEqual(process.returncode, 0, process.stderr)
                summary = json.loads((output / "_salvage_manifest.json").read_text(encoding="utf-8"))
                self.assertEqual(summary["recovered_files"], 1)
                self.assertEqual(summary["input_sha256"], hashlib.sha256(original).hexdigest())
                self.assertEqual((output / "document.txt").read_bytes(), b"verified archive data" * 100)
                self.assertFalse((root / "unsafe.txt").exists())
                summaries.append(summary)
            self.assertEqual(summaries[0]["recovered_bytes"], summaries[1]["recovered_bytes"])
            self.assertEqual(source.read_bytes(), original)

    def test_corrupt_crc_suppresses_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
                archive.writestr("corrupt.txt", b"distinct payload")
            original = bytearray(buffer.getvalue())
            original[original.find(b"distinct payload")] ^= 1
            source = root / "disk.bin"
            source.write_bytes(original)
            output = root / "mapped"
            script = Path(__file__).resolve().parents[1] / "src" / "salvage_zip.py"
            process = subprocess.run([sys.executable, str(script), str(source), str(output), "--memory-map"], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)
            summary = json.loads((output / "_salvage_manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["recovered_files"], 0)
            self.assertFalse((output / "corrupt.txt").exists())


if __name__ == "__main__":
    unittest.main()