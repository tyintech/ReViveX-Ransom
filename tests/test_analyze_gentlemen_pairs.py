import base64
import tempfile
import unittest
from pathlib import Path

from analyze_gentlemen_pairs import compare, footer, geometry


class PairAnalysisTests(unittest.TestCase):
    def test_zip_geometry(self):
        self.assertEqual(
            geometry(100000, "--super--"),
            [(0, 1000), (49500, 50500), (99000, 100000)],
        )

    def test_footer_and_changed_regions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = bytes(range(100))
            damaged = bytearray(original)
            for start, end in geometry(len(original), "--super--"):
                for offset in range(start, end):
                    damaged[offset] ^= 255
            tail = b"--eph--" + base64.b64encode(bytes(range(32))) + b"\n--marker--GENTLEMEN\nGENTLEMEN--super--\n"
            plain, encrypted = root / "a.bin", root / "a.bin.encrypted"
            plain.write_bytes(original)
            encrypted.write_bytes(damaged + tail)
            info = compare(plain, encrypted)
            self.assertEqual(info["footer_size"], 91)
            self.assertEqual(info["changed_inside_regions"], 3)
            self.assertEqual(info["changed_outside_regions"], 0)
            damaged[10] ^= 1
            encrypted.write_bytes(damaged + tail)
            self.assertEqual(compare(plain, encrypted)["changed_outside_regions"], 1)
            plain.write_bytes(original[:-1])
            with self.assertRaises(ValueError):
                compare(plain, encrypted)

    def test_invalid_footer_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.bin"
            path.write_bytes(b"not a valid footer")
            with self.assertRaises(ValueError):
                footer(path)


if __name__ == "__main__":
    unittest.main()
