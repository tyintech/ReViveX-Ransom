"""Unit tests for the rebuild stages: geometry fit, evidence scan resume,
missing-block decisions, grading and exclusive placement."""
import hashlib
import io
import json
import random
import sqlite3
import struct
import zipfile
from collections import Counter
from pathlib import Path

import pytest

from field_fixtures import MiB, build_field_case, jpeg_bytes, pdf_bytes, png_bytes, sqlite_bytes, text_bytes, zip_bytes
from revivex_block_map import evaluate_hypothesis, fit_geometry
from revivex_block_match import BlockMatcher, DEFAULTS, SCHEMA, evaluate, _png_walk
from revivex_evidence import EvidenceScan, plan_ranges, sample_probe, scan_buffer
from revivex_grading import REVIEW, SUSPECT, USABLE, grade
from revivex_source_io import BoundedSource
from revivex_stage import Cancelled, StageContext, place_exclusive


# --- geometry -----------------------------------------------------------------------
def synthetic_units(block_mib, shift_mib, blocks, anchors_per_block, seed=1):
    """guest MiB unit -> physical MiB for a shuffled BAT with the given block size and shift."""
    rng = random.Random(seed)
    slots = list(range(blocks))
    rng.shuffle(slots)
    grid = 9  # physical payload starts 9 MiB into the file, like the field case
    units = {}
    for block, slot in enumerate(slots):
        for sub in rng.sample(range(block_mib), min(block_mib, anchors_per_block)):
            u = block * block_mib + sub - shift_mib
            if u >= 0:
                units[u] = grid + slot * block_mib + sub
    return units


def test_fit_recovers_field_block_size_and_partition_shift():
    units = synthetic_units(32, 19, blocks=120, anchors_per_block=6)
    h, k, report = fit_geometry(units)
    assert (h, k) == (32, 19)
    assert report['reason'] == 'largest_consistent_block_size_with_independent_support'
    assert next(t for t in report['tried'] if t['block_mib'] == 64)['consistent'] is False


def test_fit_never_overestimates_with_thin_evidence():
    # One anchor per block: nothing pins two halves together, so the safe 1 MiB size is chosen.
    units = synthetic_units(32, 5, blocks=60, anchors_per_block=1)
    h, k, report = fit_geometry(units)
    assert h == 1
    # Two adjacent blocks agreeing once is not enough independent support for a larger size.
    units = {0: 100, 1: 101, 5: 7, 9: 40}
    assert fit_geometry(units)[0] == 1


def test_fit_prefers_vhdx_metadata_when_consistent():
    units = synthetic_units(8, 3, blocks=40, anchors_per_block=2)
    h, k, _ = fit_geometry(units, hint_mib=8)
    assert (h, k) == (8, 3)


def test_header_mismatch_refutes_a_larger_block_size():
    units = {0: 50, 1: 51, 2: 80, 3: 81, 4: 20, 5: 21, 6: 90, 7: 91}

    def header_score(h, k, starts):
        # Pretend files at unit 1 + 0.5 MiB only match when blocks are 2 MiB with the true layout.
        return (len(starts), 0) if h <= 2 else (0, 3)

    h, _, report = fit_geometry(units, header_score=header_score, min_support=1)
    assert h == 2


# --- evidence scan ------------------------------------------------------------------
def test_plan_scans_damaged_ranges_last_and_never_skips():
    ranges = plan_ranges(100 * MiB, [(0, 5), (50 * MiB + 7, 51 * MiB)])
    assert ranges == [[1 * MiB, 50 * MiB], [51 * MiB, 100 * MiB], [0, 1 * MiB], [50 * MiB, 51 * MiB]]
    assert sum(b - a for a, b in ranges) == 100 * MiB


@pytest.fixture(scope='module')
def source_case(tmp_path_factory):
    root = tmp_path_factory.mktemp('scan-case')
    return build_field_case(root)


def evidence_bytes(directory):
    return {p.name: p.read_bytes() for p in Path(directory).glob('*.bin')}


def test_evidence_scan_resume_truncates_and_matches_uninterrupted(source_case, tmp_path):
    source_path, truth = source_case
    with BoundedSource(source_path) as source:
        reference = EvidenceScan(source, tmp_path / 'ref', damaged=truth['damaged'], block=MiB).run()
        assert reference['status'] == 'finished'
        reads = Counter()
        ctx = StageContext(cancel=lambda: reads['n'] >= 5)
        original = source.readinto_at

        def counting(offset, buffer):
            reads['n'] += 1
            return original(offset, buffer)

        source.readinto_at = counting
        with pytest.raises(Cancelled):
            EvidenceScan(source, tmp_path / 'resumed', damaged=truth['damaged'], block=MiB, ctx=ctx).run()
        source.readinto_at = original
        checkpoint = json.loads((tmp_path / 'resumed' / 'checkpoint.json').read_text())
        assert checkpoint['status'] == 'running' and 0 < checkpoint['scanned'] < reference['scanned']
        with open(tmp_path / 'resumed' / 'records.bin', 'ab') as handle:  # written after the checkpoint
            handle.write(b'partial record after the last durable checkpoint')
        resumed = EvidenceScan(source, tmp_path / 'resumed', damaged=truth['damaged'], block=MiB).run()
    assert resumed['status'] == 'finished' and resumed['scanned'] == reference['scanned']
    assert evidence_bytes(tmp_path / 'resumed') == evidence_bytes(tmp_path / 'ref')
    assert resumed['counts'] == reference['counts']


def test_evidence_scan_refuses_a_changed_plan(source_case, tmp_path):
    source_path, truth = source_case
    with BoundedSource(source_path) as source:
        ctx = StageContext(cancel=lambda: True)
        with pytest.raises(Cancelled):
            EvidenceScan(source, tmp_path / 'e', damaged=truth['damaged'], block=MiB, ctx=ctx).run()
        with pytest.raises(ValueError):
            EvidenceScan(source, tmp_path / 'e', damaged=[], block=MiB).run()


def test_sample_probe_detects_surviving_ntfs_metadata(source_case, tmp_path):
    source_path, truth = source_case
    with BoundedSource(source_path) as source:
        found = sample_probe(source, damaged=truth['damaged'], samples=32)
    assert found['verdict'] == 'ntfs_metadata_found' and found['counts']['file'] > 4
    noise = tmp_path / 'noise.bin'
    noise.write_bytes(random.Random(3).randbytes(4 * MiB))
    with BoundedSource(noise) as source:
        assert sample_probe(source, samples=8)['verdict'] == 'no_ntfs_metadata_found'


def test_scan_buffer_alignment_rules():
    from field_fixtures import file_record, indx_block
    data = bytearray(64 * 1024)
    data[1024:2048] = file_record(30, [])
    data[5000:6024] = file_record(31, [])            # misaligned: ignored
    data[8192:12288] = indx_block([])
    counts = scan_buffer(bytes(data), 0)
    assert counts['file'] == 1 and counts['indx'] == 1


# --- missing-block decisions ---------------------------------------------------------
def matcher(tmp_path, rows):
    engine = BlockMatcher.__new__(BlockMatcher)
    engine.options = dict(DEFAULTS)
    engine.report = Counter()
    engine.state = sqlite3.connect(str(tmp_path / 'match.sqlite'))
    engine.state.executescript(SCHEMA)
    with engine.state:
        engine.state.executemany('INSERT INTO result VALUES(?,?,?,?,?,?,?)', rows)
        engine.state.executemany('INSERT OR IGNORE INTO pass_state VALUES(?)', [(r[2],) for r in rows])
    return engine


PLAN = {(1, 10): dict(probes=[('zip',)] * 3, headers=[], holdout=None),
        (1, 20): dict(probes=[('zip',)] * 3, headers=[], holdout=5 * MiB)}
CANDS = {(1, 10): [2 * MiB, 3 * MiB], (1, 20): [5 * MiB, 9 * MiB]}


def test_unique_candidate_with_all_probes_passing_is_accepted(tmp_path):
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 3, 0, 0, 0), (1, 10, 3 * MiB, 1, 2, 0, 0),
                                (1, 20, 5 * MiB, 3, 0, 0, 0), (1, 20, 9 * MiB, 0, 3, 0, 0)])
    accepted, holdout = engine.decide(PLAN, CANDS)
    assert [(a[1], a[2]) for a in accepted] == [((1, 10), 2 * MiB)]
    assert holdout == dict(samples=1, correct=1, wrong_slot_passed=0, matcher_enabled=True)


def test_ties_are_rejected_not_guessed(tmp_path):
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 3, 0, 0, 0), (1, 10, 3 * MiB, 4, 0, 0, 0),
                                (1, 20, 5 * MiB, 3, 0, 0, 0), (1, 20, 9 * MiB, 0, 3, 0, 0)])
    accepted, _ = engine.decide(PLAN, CANDS)
    assert accepted == [] and engine.report['ambiguous_rejected'] == 1


def test_holdout_false_positive_disables_matching(tmp_path):
    # A wrong slot passing on a block whose true slot is known means the rules are not safe here.
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 3, 0, 0, 0), (1, 20, 5 * MiB, 3, 0, 0, 0), (1, 20, 9 * MiB, 3, 0, 0, 0)])
    accepted, holdout = engine.decide(PLAN, CANDS)
    assert accepted == [] and holdout['matcher_enabled'] is False and holdout['wrong_slot_passed'] == 1


def test_weak_header_only_evidence_is_not_enough(tmp_path):
    plan = {(1, 10): dict(probes=[], headers=[(0, 'jpg'), (4096, 'jpg')], holdout=None)}
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 0, 0, 2, 0)])
    assert engine.decide(plan, {(1, 10): [2 * MiB]})[0] == []  # two headers: below the minimum


def test_three_headers_all_matching_and_unique_are_accepted(tmp_path):
    plan = {(1, 10): dict(probes=[], headers=[(0, 'jpg'), (4096, 'png'), (8192, 'pdf')], holdout=None)}
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 0, 0, 3, 0), (1, 10, 3 * MiB, 0, 0, 2, 1)])
    accepted, _ = engine.decide(plan, {(1, 10): [2 * MiB, 3 * MiB]})
    assert [(a[2], a[3]) for a in accepted] == [(2 * MiB, 'header_verified')]


def test_unread_candidates_block_a_decision(tmp_path):
    engine = matcher(tmp_path, [(1, 10, 2 * MiB, 3, 0, 0, 0)])
    accepted, _ = engine.decide({(1, 10): PLAN[(1, 10)]}, {(1, 10): [2 * MiB, 3 * MiB]})
    assert accepted == [] and engine.report['undecided_unread_candidates'] == 1


def test_zip_and_png_probes_evaluate_exact_bytes():
    member = b'x' * 500
    local = b'PK\x03\x04' + struct.pack('<HHHHHIIIHH', 20, 0, 0, 0, 0, 0x12345678, 500, 500, 5, 0) + b'a.bin' + member
    import zlib
    good = ('zip', 100, b'a.bin', 0, 500, zlib.crc32(member))
    data = bytes(100) + local
    assert evaluate(good, data, 0) == (1, 0)
    assert evaluate(good, bytes(100) + local.replace(b'a.bin', b'b.bin'), 0) == (0, 1)
    assert evaluate(('zip', 100, b'a.bin', 0, 500, 1), data, 0) == (0, 1)
    png = png_bytes(1, chunks=3, chunk_size=100)
    assert _png_walk(png, 8) == (5, 0)
    broken = bytearray(png)
    broken[40] ^= 1
    assert _png_walk(bytes(broken), 8)[1] == 1


# --- grading ---------------------------------------------------------------------------------
def test_grading_strong_checks(tmp_path):
    assert grade('a.jpg', data=jpeg_bytes(1)) == (USABLE, 'jpeg_structure')
    # Lesson 3: right header and end marker, wrong middle bytes -> not usable.
    fake = jpeg_bytes(2)
    middle = len(fake) // 2
    fake = fake[:middle] + b'\xff\x13' + fake[middle + 2:]
    assert grade('b.jpg', data=fake)[0] == SUSPECT
    assert grade('a.png', data=png_bytes(3))[0] == USABLE
    assert grade('a.png', data=png_bytes(3, corrupt=True)) == (SUSPECT, 'png_crc_mismatch')
    pdf = pdf_bytes(4, filler=3000)
    assert grade('r.pdf', data=pdf)[0] == USABLE
    shifted = pdf.replace(b'1 0 obj', b'1 0 ojb', 1)
    assert grade('r.pdf', data=shifted) == (SUSPECT, 'pdf_xref_object_mismatch')
    archive = zip_bytes(5, 3, 2000)
    assert grade('x.docx', data=archive) == (USABLE, 'zip_crc_all_members')
    damaged = bytearray(archive)
    damaged[200] ^= 0xFF
    assert grade('x.zip', data=bytes(damaged))[0] == SUSPECT
    assert grade('t.txt', data=text_bytes(6, 50))[0] == USABLE
    assert grade('t.txt', data='中文内容'.encode('gb18030'))[0] == USABLE
    assert grade('t.txt', data=b'abc\x00\x01binary')[0] == SUSPECT
    assert grade('z.dat', data=bytes(10000)) == (SUSPECT, 'all_zero_content')
    assert grade('p.pdf', data=png_bytes(7))[0] == SUSPECT  # header mismatch
    assert grade('~$lock.docx', data=b'x') == (REVIEW, 'metadata_or_lock_file')
    assert grade('empty.txt', data=b'') == (USABLE, 'empty_file')
    assert grade('unknown.xyz', data=b'\x01' * 100) == (REVIEW, 'no_format_check')
    db = tmp_path / 'x.sqlite'
    db.write_bytes(sqlite_bytes())
    assert grade('x.sqlite', path=db) == (USABLE, 'sqlite_quick_check')


# --- exclusive placement -----------------------------------------------------------------------
def test_place_exclusive_never_replaces(tmp_path):
    target, temp = tmp_path / 'file.txt', tmp_path / 'part'
    target.write_bytes(b'existing')
    temp.write_bytes(b'new')
    with pytest.raises(FileExistsError):
        place_exclusive(temp, target)
    assert target.read_bytes() == b'existing' and temp.read_bytes() == b'new'
    place_exclusive(temp, tmp_path / 'fresh.txt')
    assert (tmp_path / 'fresh.txt').read_bytes() == b'new' and not temp.exists()


def test_zero_index_is_compact_and_exact(tmp_path):
    from revivex_evidence import ZeroIndex
    values = [5 * MiB, 9 * MiB, 1 * MiB, 3 * MiB]  # two ascending runs, as written by a two-range scan
    (tmp_path / 'zero.bin').write_bytes(b''.join(struct.pack('<Q', v) for v in values) + b'\x01\x02')
    (tmp_path / 'checkpoint.json').write_text(json.dumps(dict(sizes={'zero.bin': 8 * len(values) + 2})))
    index = ZeroIndex(tmp_path)
    assert len(index) == 4 and len(index.runs) == 2
    assert all(v in index for v in values) and 2 * MiB not in index and 0 not in index
