import json
from pathlib import Path
import tempfile
import unittest

from revivex_ntfs_paths import infer_paths, load_record_paths


def link(name, parent=5, sequence=1, namespace=1):
    return dict(name=name, parent_record=parent, parent_sequence=sequence, namespace=namespace)


def record(number, names, *, offset=None, sequence=1, directory=False, in_use=True):
    return dict(status="validated_record", offset=number * 1024 if offset is None else offset,
                record_number=number, sequence=sequence, directory=directory, in_use=in_use, file_names=names)


def root():
    return record(5, [link(".")], directory=True)


class InferenceTests(unittest.TestCase):
    def test_split_physical_extents_are_inferred_never_confirmed(self):
        folder = record(8, [link("folder")], directory=True, offset=900000)
        child = record(9, [link("file.txt", 8)], offset=2000000)
        results = infer_paths([root(), folder, child], "source-a")
        self.assertEqual(results[2000000][0]["path"], "/folder/file.txt")
        self.assertEqual(results[2000000][0]["path_status"], "inferred_unverified")
        self.assertEqual(results[2000000][0]["source_id"], "source-a")

    def test_stale_sequence(self):
        child = record(9, [link("file", sequence=2)])
        self.assertEqual(infer_paths([root(), child], "s")[9216][0]["reason"], "stale_parent_sequence")

    def test_ambiguous_parent_candidate(self):
        duplicate = root()
        duplicate["offset"] += 100000
        results = infer_paths([root(), duplicate, record(9, [link("file")])], "s")
        self.assertEqual(results[9216][0]["reason"], "ambiguous_parent_record")

    def test_cycles(self):
        a = record(8, [link("a", 9)], directory=True)
        b = record(9, [link("b", 8)], directory=True)
        result = infer_paths([a, b, record(10, [link("file", 8)])], "s")
        self.assertEqual(result[10240][0]["reason"], "parent_cycle")

    def test_hardlinks_and_namespaces_preserved(self):
        child = record(9, [link("long name.txt"), link("LONGNA~1.TXT", namespace=2)])
        results = infer_paths([root(), child], "s")[9216]
        self.assertEqual([r["path"] for r in results], ["/long name.txt", "/LONGNA~1.TXT"])
        self.assertEqual(results[1]["file_name"]["namespace"], 2)

    def test_unknown_root(self):
        result = infer_paths([record(9, [link("file")])], "s")[9216][0]
        self.assertIsNone(result["path"])
        self.assertEqual(result["reason"], "parent_not_found")

    def test_explicit_cross_source_rejected(self):
        foreign = root()
        foreign["source_id"] = "foreign"
        result = infer_paths([foreign, record(9, [link("file")])], "s")
        self.assertEqual(result[5120][0]["reason"], "source_mismatch")
        self.assertEqual(result[9216][0]["reason"], "parent_not_found")

    def test_depth_guard_and_name_guard(self):
        rows = [root(), record(8, [link("folder")], directory=True), record(9, [link("file", 8)])]
        self.assertEqual(infer_paths(rows, "s", max_depth=1)[9216][0]["reason"], "depth_limit")
        self.assertEqual(infer_paths([root(), record(9, [link("../file")])], "s")[9216][0]["reason"], "unsafe_or_missing_name")

    def test_jsonl_loader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            path.write_text("\n".join(json.dumps(row) for row in [root(), record(9, [link("file")])]))
            self.assertEqual(load_record_paths(path, "s")[9216][0]["path"], "/file")
            with self.assertRaises(ValueError):
                load_record_paths(path, "s", max_records=1)
