import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from probe_vhdx import inspect
from verify_vhdx_recovery import verify


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "payload.bin").write_bytes(b"synthetic")
        self.entry = {"output": "payload.bin", "size": 9, "sha256": hashlib.sha256(b"synthetic").hexdigest()}

    def write_manifest(self):
        (self.root / "recovery_manifest.json").write_text(json.dumps({"schema_version": 1, "files": [self.entry]}))

    def test_valid_and_tampered_payload(self):
        self.write_manifest()
        self.assertEqual(verify(self.root)["verified_outputs"], 1)
        (self.root / "payload.bin").write_bytes(b"changed")
        self.assertEqual(verify(self.root)["status"], "failed")

    def test_traversal_absolute_and_windows_paths_rejected(self):
        for path in ("../payload.bin", "/payload.bin", "C:/payload.bin", "folder\\payload.bin"):
            self.entry["output"] = path
            self.write_manifest()
            self.assertEqual(verify(self.root)["status"], "failed")

    def test_missing_output_rejected(self):
        self.entry["output"] = "missing.bin"
        self.write_manifest()
        self.assertEqual(verify(self.root)["status"], "failed")

    def test_symlink_rejected(self):
        try:
            (self.root / "link.bin").symlink_to(self.root / "payload.bin")
        except OSError:
            self.skipTest("Symlinks unavailable")
        self.entry["output"] = "link.bin"
        self.write_manifest()
        self.assertEqual(verify(self.root)["status"], "failed")

    def test_probe_empty_and_tiny_files(self):
        source = self.root / "image.bin"
        source.write_bytes(b"")
        self.assertEqual(inspect(source)["size"], 0)
        source.write_bytes(b"NTFS    ")
        result = inspect(source)
        self.assertIn("Signature candidates", result["warning"])
        self.assertEqual(result["signatures"]["ntfs"][0]["offset"], 0)

    def test_missing_entry_output_fails(self):
        self.entry.pop("output")
        self.write_manifest()
        self.assertEqual(verify(self.root)["status"], "failed")

    def test_missing_source_fails_explicitly(self):
        self.write_manifest()
        report = verify(self.root, source=self.root / "absent.bin")
        self.assertEqual(report["source_verification"], "failed")
        self.assertEqual(report["status"], "failed")

    def test_source_hash_is_optional_and_mismatch_reported(self):
        self.write_manifest()
        report = verify(self.root, source=self.root / "payload.bin")
        self.assertEqual(report["source_verification"], "no_reference_hash")
        manifest = self.root / "recovery_manifest.json"
        data = json.loads(manifest.read_text())
        data["source_sha256"] = hashlib.sha256(b"other synthetic source").hexdigest()
        manifest.write_text(json.dumps(data))
        self.assertEqual(verify(self.root, source=self.root / "payload.bin")["source_verification"], "mismatch")
