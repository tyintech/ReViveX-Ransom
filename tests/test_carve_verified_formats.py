import hashlib
import base64
import sqlite3
import struct
import tempfile
import unittest
import zlib
from contextlib import closing
from pathlib import Path

from carve_verified_formats import PNG_SIGNATURE, carve, parse_png, png_rows, sqlite_extent, verify_outputs, verify_sqlite


def chunk(kind, payload):
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload))


def png(raw=b"\x00\xff\x00\x00", width=1, height=1, interlace=0):
    return (
        PNG_SIGNATURE
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, interlace))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )


class FormatCarvingTests(unittest.TestCase):
    def test_png_valid_crc_and_stream(self):
        data = png()
        end, info = parse_png(b"prefix" + data + b"suffix", 6, 6 + len(data), 1024)
        self.assertEqual(end, 6 + len(data))
        self.assertEqual(info["chunks_crc_verified"], 3)
        for broken in (data[:-1], data[:40] + bytes([data[40] ^ 1]) + data[41:]):
            with self.assertRaises(ValueError):
                parse_png(broken, 0, len(broken), 1024)

    def test_png_decoded_size_filter_and_bound(self):
        for raw in (b"\x05\xff\x00\x00", b"\x00\x00", b"\x00" * 5):
            data = png(raw)
            with self.assertRaises(ValueError):
                parse_png(data, 0, len(data), 1024)
        data = png(width=10000, height=10000)
        with self.assertRaises(ValueError):
            parse_png(data, 0, len(data), 1024)

    def test_png_interlace(self):
        self.assertEqual(png_rows(1, 1, 24, True), [(4, 1)])
        rows = png_rows(9, 9, 24, True)
        raw = b"".join((b"\x00" + b"\x00" * (size - 1)) * count for size, count in rows)
        data = png(raw, 9, 9, 1)
        _, info = parse_png(data, 0, len(data), 1024)
        self.assertTrue(info["interlaced"])
        self.assertEqual(info["decoded_scanline_bytes"], len(raw))

    def test_png_order_and_unknown_critical(self):
        data = png()
        for extra in (chunk(b"ABCD", b""), chunk(b"IDAT", zlib.compress(b"")), chunk(b"IHDR", b"\x00" * 13)):
            broken = data[:33] + extra + data[33:]
            with self.assertRaises((ValueError, zlib.error)):
                parse_png(broken, 0, len(broken), 1024)

    def test_sqlite_and_combined_carving(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "source.sqlite"
            with closing(sqlite3.connect(database_path)) as database:
                database.execute("CREATE TABLE example (id INTEGER PRIMARY KEY, value TEXT)")
                database.execute("INSERT INTO example VALUES (1, 'recovery test')")
                database.commit()
            sqlite_bytes = database_path.read_bytes()
            end, _ = sqlite_extent(sqlite_bytes, 0, len(sqlite_bytes))
            self.assertEqual(end, len(sqlite_bytes))
            self.assertEqual(verify_sqlite(database_path)["integrity_check"], "ok")
            source = root / "disk.bin"
            data = b"prefix" + png() + b"middle" + sqlite_bytes + png()
            source.write_bytes(data)
            report = carve(source, root / "output", 1048576, 1048576, 1048576)
            self.assertEqual(report["counts"]["png_unique_outputs"], 1)
            self.assertEqual(report["counts"]["png_verified_duplicates"], 1)
            self.assertEqual(report["counts"]["sqlite_unique_outputs"], 1)
            self.assertEqual(report["source_sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(source.read_bytes(), data)
            for record in report["files"]:
                self.assertEqual(hashlib.sha256((root / "output" / record["output"]).read_bytes()).hexdigest(), record["sha256"])
            from verify_vhdx_recovery import verify
            generic = verify(root / "output", [root / "output/manifest.json"], source)
            self.assertEqual(generic["status"], "completed", generic)
            self.assertEqual(generic["verified_outputs"], 2)
            verification = verify_outputs(root / "output", report["source_sha256"])
            self.assertEqual(verification["verified_unique_files"], {"png": 1, "sqlite": 1})
            with self.assertRaises(ValueError):
                carve(source, root / "output", 1048576, 1048576, 1048576)
            with self.assertRaises(ValueError):
                sqlite_extent(sqlite_bytes, 0, len(sqlite_bytes) - 1)
            damaged = bytearray(sqlite_bytes)
            damaged[28:32] = b"\xff\xff\xff\xff"
            with self.assertRaises(ValueError):
                sqlite_extent(damaged, 0, len(damaged))

    def test_output_limit_records_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "disk.bin"
            source.write_bytes(png())
            report = carve(source, root / "output", 1048576, 1, 1048576)
            self.assertEqual(report["counts"]["png_rejected"], 1)
            self.assertEqual(report["files"], [])
            self.assertIn("png: Total output byte limit exceeded", report["rejection_reasons"])

    def test_excluded_interval_and_verification_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "disk.bin"
            data = bytearray(10000)
            sample = png()
            data[:len(sample)] = sample
            data[1000:1000 + len(sample)] = sample
            tail = b"--eph--" + base64.b64encode(bytes(range(32))) + b"\n--marker--GENTLEMEN\nGENTLEMEN--super--\n"
            source.write_bytes(data + tail)
            report = carve(source, root / "output", 1048576, 1048576, 1048576, True)
            self.assertEqual(report["counts"]["png_rejected"], 1)
            self.assertEqual(report["counts"]["png_unique_outputs"], 1)
            (root / "output" / report["files"][0]["output"]).write_bytes(b"corrupt output")
            with self.assertRaises(ValueError):
                verify_outputs(root / "output", report["source_sha256"])

    def test_corrupt_sqlite_is_rejected_and_candidate_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "original.sqlite"
            with closing(sqlite3.connect(database_path)) as database:
                database.execute("CREATE TABLE example (value TEXT)")
                database.commit()
            data = bytearray(database_path.read_bytes())
            data[100] = 0xff
            source = root / "disk.bin"
            source.write_bytes(data)
            report = carve(source, root / "output", 1048576, 1048576, 1048576)
            self.assertEqual(report["counts"]["sqlite_rejected"], 1)
            self.assertFalse(list((root / "output").glob("candidate_*.sqlite")))


if __name__ == "__main__":
    unittest.main()
