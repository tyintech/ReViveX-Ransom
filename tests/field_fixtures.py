"""Small synthetic stand-in for the field case: a dynamic VHDX with two NTFS
volumes whose header, region tables, BAT and metadata are destroyed.

Real on-disk structures (not mocks): NTFS boot sectors, 1024-byte FILE records
with update-sequence fixups, 4096-byte INDX blocks, $I30 allocation runs,
fragmented $DATA runs, resident files, a reused record number (stale parent
sequence) and a disk image stored inside a volume. Payload blocks are placed
out of order. The Gentlemen footer and its inferred ranges match the real
format; those ranges are overwritten with noise. Every file's ground truth
(path, bytes, physical extents) is returned so tests can check outcomes.

Total size stays below ~20 MiB.
"""
from __future__ import annotations

import base64
import io
import os
import random
import sqlite3
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path

from vhdx_fixtures import build_vhdx

MiB = 1024 * 1024
CLUSTER = 4096


# --- NTFS structures ------------------------------------------------------------
def _attr_resident(kind, value, name='', ident=0):
    encoded = name.encode('utf-16le')
    value_offset = (24 + len(encoded) + 7) // 8 * 8
    raw = bytearray((value_offset + len(value) + 7) // 8 * 8)
    struct.pack_into('<IIBBHHH', raw, 0, kind, len(raw), 0, len(encoded) // 2, 24 if name else 0, 0, ident)
    struct.pack_into('<IH', raw, 16, len(value), value_offset)
    raw[24:24 + len(encoded)] = encoded
    raw[value_offset:value_offset + len(value)] = value
    return bytes(raw)


def _filename_value(name, parent, parent_seq, namespace=1):
    encoded = name.encode('utf-16le')
    raw = bytearray(66 + len(encoded))
    struct.pack_into('<Q', raw, 0, parent | parent_seq << 48)
    struct.pack_into('<Q', raw, 16, 133_000_000_000_000_000)
    raw[64:66] = bytes((len(encoded) // 2, namespace))
    raw[66:] = encoded
    return bytes(raw)


def _attr_nonresident(kind, runs, size, name='', ident=1):
    pairs, previous = bytearray(), 0
    for lcn, count in runs:
        n = max(1, (count.bit_length() + 8) // 8)
        if lcn is None:
            pairs.append(n)
            pairs += count.to_bytes(n, 'little')
            continue
        delta, previous = lcn - previous, lcn
        d = next(k for k in range(1, 9) if -(1 << (8 * k - 1)) <= delta < (1 << (8 * k - 1)))
        pairs.append(n | d << 4)
        pairs += count.to_bytes(n, 'little') + delta.to_bytes(d, 'little', signed=True)
    pairs.append(0)
    encoded = name.encode('utf-16le')
    mapping = (64 + len(encoded) + 7) // 8 * 8
    raw = bytearray((mapping + len(pairs) + 7) // 8 * 8)
    struct.pack_into('<IIBBHHH', raw, 0, kind, len(raw), 1, len(encoded) // 2, 64 if name else 0, 0, ident)
    clusters = sum(n for _, n in runs)
    struct.pack_into('<QQH', raw, 16, 0, clusters - 1, mapping)
    struct.pack_into('<QQQ', raw, 40, clusters * CLUSTER, size, size)
    raw[64:64 + len(encoded)] = encoded
    raw[mapping:mapping + len(pairs)] = pairs
    return bytes(raw)


def _fixup(raw, sectors, usa_offset):
    raw[usa_offset:usa_offset + 2] = b'\x2a\x00'
    for i in range(1, sectors + 1):
        raw[usa_offset + 2 * i:usa_offset + 2 * i + 2] = raw[i * 512 - 2:i * 512]
        raw[i * 512 - 2:i * 512] = b'\x2a\x00'
    return bytes(raw)


def file_record(number, attrs, *, flags=1, seq=1):
    raw = bytearray(1024)
    raw[:4] = b'FILE'
    struct.pack_into('<HH', raw, 4, 48, 3)
    struct.pack_into('<Q', raw, 8, 1000 + number)
    struct.pack_into('<HH', raw, 16, seq, 1)
    body = b''.join(attrs) + b'\xff\xff\xff\xff'
    if 56 + len(body) > 1016:
        raise ValueError('record too large')
    struct.pack_into('<HHII', raw, 20, 56, flags, 56 + len(body), 1024)
    struct.pack_into('<I', raw, 44, number)
    raw[56:56 + len(body)] = body
    return _fixup(raw, 2, 48)


def indx_block(entries):
    raw = bytearray(4096)
    raw[:4] = b'INDX'
    struct.pack_into('<HH', raw, 4, 40, 9)
    position = 64
    for child, child_seq, key in entries:
        length = (16 + len(key) + 7) // 8 * 8
        struct.pack_into('<QHHI', raw, position, child | child_seq << 48, length, len(key), 0)
        raw[position + 16:position + 16 + len(key)] = key
        position += length
    struct.pack_into('<QHHI', raw, position, 0, 16, 0, 2)
    position += 16
    struct.pack_into('<II', raw, 24, 40, position - 24)
    struct.pack_into('<I', raw, 32, 4096 - 24)
    if position > 4000:
        raise ValueError('directory too large for one INDX block')
    return _fixup(raw, 8, 40)


def boot_sector(total_sectors, mft_lcn, serial):
    raw = bytearray(512)
    raw[:3] = b'\xeb\x52\x90'
    raw[3:11] = b'NTFS    '
    struct.pack_into('<HB', raw, 11, 512, CLUSTER // 512)
    struct.pack_into('<QQQ', raw, 40, total_sectors, mft_lcn, 2)
    struct.pack_into('<b', raw, 64, -10)
    struct.pack_into('<b', raw, 68, 1)
    struct.pack_into('<Q', raw, 72, serial)
    raw[510:512] = b'\x55\xaa'
    return bytes(raw)


class Volume:
    """Builds one NTFS volume in memory and keeps ground truth for every file."""

    def __init__(self, size, label, *, mft_lcn=16, mft_records=64, serial=1):
        self.size, self.label, self.serial = size, label, serial
        self.data = bytearray(size)
        self.mft_lcn, self.mft_records = mft_lcn, mft_records
        self.cursor = mft_lcn + mft_records * 1024 // CLUSTER
        self.used = set(range(0, self.cursor))
        self.records = {}  # number -> dict
        self.next_number = 24
        self.dirs = {5: dict(name='.', parent=5, seq=5, children=[], indx=None)}
        self.records[5] = dict(kind='dir', name='.', parent=5, parent_seq=5, seq=5)
        self.files = []

    def _alloc(self, clusters, at=None):
        start = self.cursor if at is None else at
        for lcn in range(start, start + clusters):
            if lcn in self.used or lcn * CLUSTER >= self.size - 4096:
                raise ValueError(f'cluster {lcn} unavailable in {self.label}')
            self.used.add(lcn)
        if at is None:
            self.cursor = start + clusters
        return start

    def number(self, number=None):
        if number is None:
            number = self.next_number
            self.next_number += 1
        return number

    def mkdir(self, name, parent=5, *, at=None, number=None, seq=1):
        number = self.number(number)
        lcn = self._alloc(1, at)
        self.dirs[number] = dict(name=name, parent=parent, seq=seq, children=[], indx=lcn)
        self.records[number] = dict(kind='dir', name=name, parent=parent, parent_seq=self.records[parent]['seq'], seq=seq)
        self.dirs[parent]['children'].append(number)
        return number

    def add(self, name, parent, content, *, at=None, runs=None, number=None, seq=1, parent_seq=None, resident=False,
            deleted=False, reused_runs=None):
        """``deleted``: the record is marked not in use and removed from its folder index.
        ``reused_runs``: a deleted file whose clusters now belong to another (live) file."""
        number = self.number(number)
        record = dict(kind='file', name=name, parent=parent, seq=seq, content=bytes(content), deleted=deleted,
                      parent_seq=self.records[parent]['seq'] if parent_seq is None else parent_seq)
        if reused_runs is not None:
            record['runs'] = list(reused_runs)
        elif resident:
            record['resident'] = True
        else:
            clusters = max(1, -(-len(content) // CLUSTER))
            if runs is None:
                runs = [(self._alloc(clusters, at), clusters)]
            else:
                runs = [(self._alloc(n, lcn), n) for lcn, n in runs]
                if sum(n for _, n in runs) < clusters:
                    raise ValueError('runs too short')
            record['runs'] = runs
            position = 0
            for lcn, count in runs:
                part = content[position:position + count * CLUSTER]
                self.data[lcn * CLUSTER:lcn * CLUSTER + len(part)] = part
                position += count * CLUSTER
        self.records[number] = record
        if parent in self.dirs and record['parent_seq'] == self.records[parent]['seq'] and not deleted:
            self.dirs[parent]['children'].append(number)
        return number

    def path(self, number):
        parts = []
        while number != 5:
            record = self.records[number]
            parts.append(record['name'])
            number = record['parent']
        return '/'.join(reversed(parts))

    def finalize(self):
        self.dirs[5]['indx'] = self._alloc(1)
        mft = bytearray(self.mft_records * 1024)
        system = {0: ('$MFT', [_attr_nonresident(0x80, [(self.mft_lcn, len(mft) // CLUSTER)], len(mft))]),
                  1: ('$MFTMirr', []), 2: ('$LogFile', []),
                  3: ('$Volume', [_attr_resident(0x60, self.label.encode('utf-16le'))]), 4: ('$AttrDef', []),
                  6: ('$Bitmap', []), 7: ('$Boot', []), 8: ('$BadClus', []), 9: ('$Secure', []), 10: ('$UpCase', [])}
        for number, (name, extra) in system.items():
            attrs = [_attr_resident(0x30, _filename_value(name, 5, 5))] + extra
            mft[number * 1024:(number + 1) * 1024] = file_record(number, attrs, seq=number or 1)
        for number, record in self.records.items():
            attrs = [_attr_resident(0x30, _filename_value(record['name'], record['parent'], record['parent_seq']))]
            if record['kind'] == 'dir':
                attrs.append(_attr_nonresident(0xA0, [(self.dirs[number]['indx'], 1)], CLUSTER, name='$I30', ident=2))
                flags = 3
            elif record.get('resident'):
                attrs.append(_attr_resident(0x80, record['content'], ident=1))
                flags = 0 if record.get('deleted') else 1
            else:
                attrs.append(_attr_nonresident(0x80, record['runs'], len(record['content'])))
                flags = 0 if record.get('deleted') else 1
            mft[number * 1024:(number + 1) * 1024] = file_record(number, attrs, flags=flags, seq=record['seq'])
        self.data[self.mft_lcn * CLUSTER:self.mft_lcn * CLUSTER + len(mft)] = mft
        for number, directory in self.dirs.items():
            entries = []
            for child in sorted(directory['children'], key=lambda c: self.records[c]['name'].lower()):
                record = self.records[child]
                entries.append((child, record['seq'], _filename_value(record['name'], number, self.records[number]['seq'])))
            lcn = directory['indx']
            self.data[lcn * CLUSTER:(lcn + 1) * CLUSTER] = indx_block(entries)
        boot = boot_sector(self.size // 512 - 1, self.mft_lcn, self.serial)
        self.data[:512] = boot
        self.data[-512:] = boot
        self.files = [dict(number=n, path=self.path(n), content=r['content'], runs=r.get('runs'), resident=r.get('resident', False),
                           deleted=r.get('deleted', False))
                      for n, r in self.records.items() if r['kind'] == 'file']
        return bytes(self.data)


# --- file contents with real structure -----------------------------------------
def png_bytes(seed, chunks=6, chunk_size=20000, corrupt=False):
    rng = random.Random(seed)
    def chunk(kind, body):
        return struct.pack('>I', len(body)) + kind + body + struct.pack('>I', zlib.crc32(body, zlib.crc32(kind)))
    out = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 64, 64, 8, 2, 0, 0, 0))
    for _ in range(chunks):
        out += chunk(b'IDAT', rng.randbytes(chunk_size))
    out += chunk(b'IEND', b'')
    if corrupt:
        out = bytearray(out)
        out[60] ^= 0xFF
        out = bytes(out)
    return out


def jpeg_bytes(seed, size=30000):
    rng = random.Random(seed)
    entropy = bytes(b if b != 0xFF else 0x7F for b in rng.randbytes(size))
    segment = lambda marker, body: b'\xff' + bytes([marker]) + struct.pack('>H', len(body) + 2) + body
    return (b'\xff\xd8' + segment(0xE0, b'JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00') +
            segment(0xDB, bytes(65)) + segment(0xC0, b'\x08\x00\x40\x00\x40\x01\x01\x11\x00') +
            segment(0xC4, bytes(29)) + segment(0xDA, b'\x01\x01\x00\x00\x3f\x00') + entropy + b'\xff\xd9')


def pdf_bytes(seed, filler=150000):
    rng = random.Random(seed)
    stream = base64.b64encode(rng.randbytes(filler * 3 // 4))
    objects = [b'<< /Type /Catalog /Pages 2 0 R >>', b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
               b'<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>',
               b'<< /Length %d >>\nstream\n' % len(stream) + stream + b'\nendstream']
    out, offsets = bytearray(b'%PDF-1.4\n'), []
    for i, body in enumerate(objects, 1):
        offsets.append(len(out))
        out += b'%d 0 obj\n' % i + body + b'\nendobj\n'
    xref = len(out)
    out += b'xref\n0 %d\n0000000000 65535 f \n' % (len(objects) + 1)
    for offset in offsets:
        out += b'%010d 00000 n \n' % offset
    out += b'trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n' % (len(objects) + 1, xref)
    return bytes(out)


def zip_bytes(seed, members, member_size):
    rng = random.Random(seed)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED) as archive:
        for i in range(members):
            archive.writestr(f'part{i:03d}.bin', rng.randbytes(member_size))
    return buffer.getvalue()


def sqlite_bytes():
    with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
        path = Path(directory) / 'x.sqlite'
        with sqlite3.connect(path) as db:
            db.execute('CREATE TABLE t(a, b)')
            db.executemany('INSERT INTO t VALUES(?,?)', [(i, 'row %d' % i * 4) for i in range(400)])
        db.close()
        return path.read_bytes()


def pe_bytes(seed):
    raw = bytearray(random.Random(seed).randbytes(12288))
    raw[:2] = b'MZ'
    struct.pack_into('<I', raw, 60, 128)
    raw[128:132] = b'PE\0\0'
    struct.pack_into('<HH', raw, 132, 0x14c, 1)
    struct.pack_into('<H', raw, 148, 224)
    struct.pack_into('<II', raw, 152 + 224 + 16, 4096, 4096)
    return bytes(raw)


def text_bytes(seed, lines):
    rng = random.Random(seed)
    words = ['恢复', 'recovery', 'block', '文件', 'volume', 'index', 'report', '数据']
    return '\n'.join(' '.join(rng.choice(words) for _ in range(12)) for _ in range(lines)).encode('utf-8')


# --- disk -----------------------------------------------------------------------
def gentlemen_footer(mode=b'--super--'):
    key = base64.b64encode(bytes(range(32)))
    return b'--eph--' + key + b'\n--marker--GENTLEMEN\nGENTLEMEN' + mode + b'\n'


def geometry(size, ratio=(1, 100)):
    chunk = size * ratio[0] // ratio[1]
    middle = (size - 3 * chunk) // 2 + chunk
    return [(0, chunk), (middle, middle + chunk), (2 * middle, 2 * middle + chunk)]


def build_field_case(directory):
    """Write the damaged VHDX into ``directory``; return (path, truth)."""
    directory = Path(directory)
    rng = random.Random(1234)
    # Volume A (system), partition at guest 1 MiB.
    a = Volume(2 * MiB, 'SYSTEM', serial=0xA)
    windows = a.mkdir('Windows')
    system32 = a.mkdir('System32', windows)
    users = a.mkdir('Users', at=200)
    alice = a.mkdir('alice', users)
    a.add('kernel_helper.dll', system32, pe_bytes(1))
    a.add('desktop.txt', alice, text_bytes(2, 300))
    a.add('photo.jpg', alice, jpeg_bytes(3), at=260)
    a.add('tiny.ini', alice, b'[x]\nkey=1\n', resident=True)
    volume_a = a.finalize()

    # Embedded disk image stored as a file inside volume B (another LCN space).
    inner = Volume(512 * 1024, 'INNER', mft_lcn=4, mft_records=32, serial=0xC)
    secret = inner.mkdir('InnerOnly')
    inner.add('inner_secret.png', secret, png_bytes(40, chunks=2, chunk_size=3000))
    inner.add('inner_note.txt', secret, text_bytes(41, 40))
    inner.add('inner_doc.pdf', secret, pdf_bytes(42, filler=9000))
    inner.add('inner_pic.jpg', 5, jpeg_bytes(43, size=5000))
    inner_image = inner.finalize()

    # Volume B (data), partition at guest 3 MiB + 192 KiB (not block-aligned).
    b = Volume(10 * MiB, 'DATA', serial=0xB)
    docs = b.mkdir('Documents')                       # INDX in block of the MFT
    photos = b.mkdir('Photos', at=300)
    archive = b.mkdir('Archive', at=560)
    projects = b.mkdir('Projects', at=1290)
    deep = b.mkdir('Deep', projects, at=2240)
    b.add('report.pdf', docs, pdf_bytes(10))
    b.add('notes.txt', docs, '短笔记 short note'.encode('utf-8'), resident=True)
    b.add('frag.txt', docs, text_bytes(11, 900), runs=[(120, 9), (470, 12)])
    b.add('broken.png', docs, png_bytes(12, corrupt=True))
    b.add('a.png', photos, png_bytes(13), at=310)
    b.add('b.jpg', photos, jpeg_bytes(14), at=350)
    b.add('Thumbs.db', photos, b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + rng.randbytes(9000), at=370)
    b.add('unknown.bin', photos, rng.randbytes(20000), at=380)
    # A ZIP spanning several blocks; its middle block has no anchor and no file start.
    big = zip_bytes(15, members=26, member_size=110 * 1024)
    b.add('big.zip', archive, big, at=570)
    b.add('disk.img', archive, inner_image, at=1300)
    b.add('plan.txt', deep, text_bytes(16, 1200), at=2250)
    b.add('state.sqlite', deep, sqlite_bytes(), at=2280)
    b.add('slides.pptx', deep, zip_bytes(17, members=3, member_size=9000), at=2300)
    victim = b.add('victim.bin', projects, rng.randbytes(3 * MiB + 100 * 1024), at=1440)
    # Record-number reuse: record 60 used to be a folder; it is now a file (seq 2).
    reused = b.add('reused.txt', 5, b'I reuse record sixty\n' * 50, number=60, seq=2, at=1294)
    orphan = b.add('orphan.txt', 60, b'parent was deleted\n' * 40, parent_seq=1, at=1296)
    # Deleted files: free clusters (recoverable), clusters reused by a live file (must be refused),
    # and a deleted resident file whose bytes are still inside its MFT record.
    b.add('old_draft.pdf', docs, pdf_bytes(21, filler=20000), at=140, deleted=True)
    b.add('tmp_note.txt', docs, '删除前的笔记 note before deletion'.encode('utf-8'), resident=True, deleted=True)
    reused_deleted = b.add('gone.jpg', photos, jpeg_bytes(22), reused_runs=[(310, 8)], deleted=True)
    volume_b = b.finalize()

    # Guest disk: MBR + two partitions, 1 MiB blocks; blocks 0-13 written, block 14 never written.
    p_a, p_b = 1 * MiB, 3 * MiB + 192 * 1024
    guest = bytearray(15 * MiB)
    guest[510:512] = b'\x55\xaa'
    for i, (start, length) in enumerate(((p_a, len(volume_a)), (p_b, len(volume_b)))):
        struct.pack_into('<BBBBBBBBII', guest, 446 + 16 * i, 0, 0, 0, 0, 7, 0, 0, 0, start // 512, length // 512)
    guest[p_a:p_a + len(volume_a)] = volume_a
    guest[p_b:p_b + len(volume_b)] = volume_b
    states = [6] * 14 + [0]
    # Physical order (non-linear BAT). Guest blocks 6 and 7 hold only the middle of big.zip and are
    # placed away from their neighbours: no anchor, no file start, interpolation impossible.
    # Victim blocks 9/10 sit where the inferred middle encryption range falls; block 13 (volume
    # tail, nothing needed) takes the inferred tail range.
    order = [11, 12, 3, 4, 9, 10, 0, 1, 2, 6, 8, 5, 7, 13]
    body = 4 * MiB + len(order) * MiB
    damaged = geometry(body)
    assert sorted({(o - 4 * MiB) // MiB for o in (damaged[1][0], damaged[1][1] - 1)}) == [4, 5]
    assert (damaged[2][0] - 4 * MiB) // MiB == 13 and damaged[2][0] % MiB > 600 * 1024
    zip_first, isolated = 5, 6
    path = directory / 'victim-disk.vhdx.locked'
    build_vhdx(path, bytes(guest), block_size=MiB, states=states, order=order)
    raw = bytearray(path.read_bytes())
    assert len(raw) == body
    noise = random.Random(99)
    raw[:4 * MiB] = noise.randbytes(4 * MiB)  # headers, region tables, BAT and metadata destroyed
    for start, end in damaged:
        raw[start:end] = noise.randbytes(end - start)
    raw += gentlemen_footer()
    path.write_bytes(raw)

    slot_of = {block: 4 * MiB + n * MiB for n, block in enumerate(order)}

    def physical(volume_offset, partition):
        g = partition + volume_offset
        return slot_of.get(g // MiB, None), g % MiB

    truth = []
    for label, volume, partition in (('SYSTEM', a, p_a), ('DATA', b, p_b)):
        for entry in volume.files:
            extents = []
            for lcn, count in entry['runs'] or ():
                offset, end = lcn * CLUSTER, lcn * CLUSTER + min(count * CLUSTER, len(entry['content']))
                while offset < end:
                    slot, within = physical(offset, partition)
                    take = min(end - offset, MiB - within)
                    extents.append((slot + within, take))
                    offset += take
            truth.append(dict(volume=label, number=entry['number'], path=entry['path'], content=entry['content'],
                              resident=entry['resident'], deleted=entry['deleted'], extents=extents))
    inner_names = [f['path'].rsplit('/', 1)[-1] for f in inner.files]
    return path, dict(files=truth, damaged=damaged, order=order, partitions=(p_a, p_b), inner_names=inner_names,
                      reused=reused, orphan=orphan, victim=victim, reused_deleted=reused_deleted, isolated_block=isolated, zip_first=zip_first)
