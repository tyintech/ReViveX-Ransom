"""Grade recovered files: usable / needs review / suspect damaged.

"Written" is not "recovered" (field lesson 9): every file gets a format
check that reads its structure, not just its first and last bytes. A JPEG's
header plus end marker is NOT enough (lesson 3: that weak check approved
1,211 wrong files out of 1,342), so JPEG entropy data is scanned for invalid
markers. Checks prove structure only, never that content is original.

Validators read through a ``Blob`` (bounded random access over an in-memory
buffer or a recovered file); nothing here ever touches the source image.
"""
from __future__ import annotations

import io
import os
import re
import sqlite3
import struct
import zipfile
import zlib

USABLE, REVIEW, SUSPECT = 'usable', 'needs_review', 'suspect_damaged'
GRADES = (USABLE, REVIEW, SUSPECT)
THUMBNAIL_NAMES = {'thumbs.db', 'ehthumbs.db', 'ehthumbs_vista.db'}
TEXT = {'htm', 'html', 'xml', 'js', 'css', 'txt', 'csv', 'obj', 'mtl', 'ini', 'json', 'svg', 'log', 'inf', 'bat', 'cmd',
        'md', 'sql', 'php', 'asp', 'aspx', 'config', 'xaml', 'resx', 'vb', 'cs', 'java', 'py', 'h', 'c', 'cpp', 'reg', 'yml',
        'yaml', 'tsv', 'srt'}
OLE = {'doc', 'xls', 'ppt', 'msg', 'vsd', 'pub', 'msi', 'mpp', 'wps', 'et', 'dps', 'db'}
ZIPS = {'docx', 'xlsx', 'pptx', 'zip', 'jar', 'apk', 'vsdx', 'odt', 'ods', 'odp', 'cdr', 'xps', 'epub', 'kmz'}
EXPECT = {'jpg': 'jpg', 'jpeg': 'jpg', 'png': 'png', 'pdf': 'pdf', 'gif': 'gif', 'zip': 'zip', 'doc': 'ole', 'xls': 'ole',
          'ppt': 'ole', 'msg': 'ole', 'dwg': 'dwg', 'rar': 'rar', '7z': '7z', 'exe': 'mz', 'dll': 'mz', 'mp4': 'mp4',
          'mov': 'mp4', 'avi': 'riff', 'wav': 'riff', 'tif': 'tif', 'tiff': 'tif', 'psd': 'psd', **{e: 'zip' for e in ZIPS}}
MP4 = {'mp4', 'mov', 'm4v', 'm4a', '3gp'}
PE = {'exe', 'dll', 'sys', 'ocx', 'mui', 'cpl', 'drv', 'efi', 'scr'}
CHUNK = 4 * 1024 * 1024


class Blob:
    """Bounded random access over bytes or a file path."""

    def __init__(self, data=None, path=None):
        self.data, self.path = data, path
        self.handle = None
        self.size = len(data) if data is not None else os.path.getsize(path)

    def read(self, offset, length):
        if offset < 0 or length <= 0 or offset >= self.size:
            return b''
        length = min(length, self.size - offset)
        if self.data is not None:
            return bytes(self.data[offset:offset + length])
        if self.handle is None:
            self.handle = open(self.path, 'rb')
        self.handle.seek(offset)
        return self.handle.read(length)

    def chunks(self, start=0, size=CHUNK):
        position = start
        while position < self.size:
            piece = self.read(position, size)
            if not piece:
                return
            yield position, piece
            position += len(piece)

    def stream(self):
        return io.BytesIO(self.data) if self.data is not None else open(self.path, 'rb')

    def close(self):
        if self.handle:
            self.handle.close()
            self.handle = None


def detect(head):
    for magic, kind in ((b'\xff\xd8\xff', 'jpg'), (b'\x89PNG', 'png'), (b'%PDF', 'pdf'), (b'PK\x03\x04', 'zip'),
                        (b'\xd0\xcf\x11\xe0', 'ole'), (b'GIF8', 'gif'), (b'RIFF', 'riff'), (b'MZ', 'mz'), (b'Rar!', 'rar'),
                        (b'7z\xbc\xaf', '7z'), (b'AC10', 'dwg'), (b'II*\x00', 'tif'), (b'MM\x00*', 'tif'),
                        (b'8BPS', 'psd'), (b'SQLite format 3\x00', 'sqlite')):
        if head.startswith(magic):
            return kind
    if head[4:8] == b'ftyp':
        return 'mp4'
    return 'other'


# --- structural checks (each returns (grade, detail)) ---------------------------
def check_jpeg(blob):
    """Walk segments to SOS, then scan entropy data: only RSTn, stuffing, EOI or a new segment may follow 0xFF."""
    position = 2
    sos_seen = False
    while position + 4 <= blob.size:
        marker = blob.read(position, 4)
        if marker[0] != 0xFF:
            return SUSPECT, 'jpeg_bad_segment_marker'
        kind = marker[1]
        if kind == 0xFF:
            position += 1
            continue
        if kind == 0xD9:
            return (USABLE, 'jpeg_structure') if sos_seen else (SUSPECT, 'jpeg_no_scan')
        if 0xD0 <= kind <= 0xD7 or kind == 0x01:
            position += 2
            continue
        length = struct.unpack('>H', marker[2:4])[0]
        if length < 2:
            return SUSPECT, 'jpeg_bad_segment_length'
        position += 2 + length
        if kind != 0xDA:
            continue
        sos_seen = True
        # Entropy-coded data until the next real marker.
        carry = b''
        for offset, piece in blob.chunks(position):
            data = carry + piece
            base = offset - len(carry)
            index = data.find(b'\xff')
            while index >= 0 and index + 1 < len(data):
                following = data[index + 1]
                if following == 0x00 or 0xD0 <= following <= 0xD7 or following == 0xFF:
                    index = data.find(b'\xff', index + 1)
                    continue
                if following == 0xD9:
                    tail = blob.read(base + index + 2, 1 << 20).rstrip(b'\0')
                    return (USABLE, 'jpeg_structure') if not tail else (USABLE, 'jpeg_structure_trailing_data')
                if following in (0xC4, 0xDA, 0xDD, 0xFE) or 0xE0 <= following <= 0xEF or following in (0xDB, 0xC0, 0xC2):
                    position = base + index  # progressive JPEG: another segment/scan
                    break
                return SUSPECT, f'jpeg_invalid_marker_in_scan_ff{following:02x}'
            else:
                carry = data[-1:] if data.endswith(b'\xff') else b''
                continue
            break
        else:
            return SUSPECT, 'jpeg_no_end_marker'
    return SUSPECT, 'jpeg_truncated'


def check_png(blob):
    position = 8
    while position + 12 <= blob.size:
        length, kind = struct.unpack('>I4s', blob.read(position, 8))
        if length > 0x7FFFFFFF or not kind.isalpha():
            return SUSPECT, 'png_bad_chunk_header'
        crc, remaining, offset = zlib.crc32(kind), length, position + 8
        while remaining:
            piece = blob.read(offset, min(remaining, CHUNK))
            if not piece:
                return SUSPECT, 'png_truncated'
            crc = zlib.crc32(piece, crc)
            offset += len(piece)
            remaining -= len(piece)
        stored = blob.read(offset, 4)
        if len(stored) < 4 or struct.unpack('>I', stored)[0] != crc:
            return SUSPECT, 'png_crc_mismatch'
        position = offset + 4
        if kind == b'IEND':
            return USABLE, 'png_chunk_crc'
    return SUSPECT, 'png_truncated'


def check_pdf(blob):
    tail = blob.read(max(0, blob.size - 4096), 4096)
    if b'%%EOF' not in tail:
        return SUSPECT, 'pdf_no_eof'
    match = re.search(rb'startxref\s+(\d+)', tail[tail.rfind(b'startxref'):]) if b'startxref' in tail else None
    if not match:
        return SUSPECT, 'pdf_no_startxref'
    target = int(match[1])
    head = blob.read(target, 64 * 1024)
    if head.startswith(b'xref'):
        checked = 0
        body = head[4:]
        section = re.match(rb'\s*(\d+) (\d+)\s', body)
        if section:
            first = int(section[1])
            for i, entry in enumerate(re.finditer(rb'(\d{10}) (\d{5}) ([nf])', body[section.end():])):
                if i >= int(section[2]) or checked >= 200:
                    break
                if entry[3] == b'n':
                    window = blob.read(int(entry[1]), 40)
                    if not re.match(rb'\s*%d\s+%d\s+obj' % (first + i, int(entry[2])), window):
                        return SUSPECT, 'pdf_xref_object_mismatch'
                    checked += 1
        return USABLE, f'pdf_xref_objects_{checked}'
    if re.match(rb'\s*\d+\s+\d+\s+obj', head[:40]) and b'/XRef' in head[:4096]:
        return USABLE, 'pdf_xref_stream'
    return SUSPECT, 'pdf_startxref_target_invalid'


def check_zip(blob):
    try:
        with blob.stream() as handle, zipfile.ZipFile(handle) as archive:
            bad = archive.testzip()
    except (zipfile.BadZipFile, zlib.error, EOFError, NotImplementedError, RuntimeError, ValueError, OSError) as error:
        return SUSPECT, f'zip_{type(error).__name__}'
    return (USABLE, 'zip_crc_all_members') if bad is None else (SUSPECT, 'zip_member_crc_failed')


def check_ole(blob):
    header = blob.read(0, 512)
    if header[:8] != b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return SUSPECT, 'ole_header'
    sector = 1 << struct.unpack_from('<H', header, 30)[0]
    if sector not in (512, 4096):
        return SUSPECT, 'ole_sector_size'
    nfat, directory = struct.unpack_from('<II', header, 44)
    sectors = (blob.size - sector) // sector + 1
    fats = struct.unpack_from('<109I', header, 76)[:min(nfat, 109)]
    if any(x >= sectors for x in fats) or directory >= sectors:
        return SUSPECT, 'ole_fat_out_of_file'
    fat = []
    for x in fats:
        raw = blob.read(sector + x * sector, sector)
        if len(raw) < sector:
            return SUSPECT, 'ole_fat_truncated'
        fat += struct.unpack(f'<{sector // 4}I', raw)
    current, hops, names = directory, 0, 0
    while current < 0xFFFFFFFA:
        if current >= len(fat) or hops > 100000:
            return SUSPECT, 'ole_directory_chain'
        raw = blob.read(sector + current * sector, sector)
        for i in range(0, len(raw) - 127, 128):
            entry = raw[i:i + 128]
            length = struct.unpack_from('<H', entry, 64)[0]
            if entry[66] in (1, 2, 5) and 2 <= length <= 64:
                names += 1
        current, hops = fat[current], hops + 1
    return (USABLE, 'ole_fat_directory') if names else (SUSPECT, 'ole_no_directory_entries')


def check_tif(blob):
    head = blob.read(0, 8)
    if head[:4] not in (b'II*\x00', b'MM\x00*'):
        return SUSPECT, 'tiff_header'
    u16, u32 = ('<H', '<I') if head[:2] == b'II' else ('>H', '>I')
    offset, seen = struct.unpack(u32, head[4:8])[0], set()
    while offset:
        if offset in seen or offset + 2 > blob.size or len(seen) > 1000:
            return SUSPECT, 'tiff_ifd_chain'
        seen.add(offset)
        count = struct.unpack(u16, blob.read(offset, 2))[0]
        table = blob.read(offset + 2, 12 * count + 4)
        if len(table) < 12 * count + 4:
            return SUSPECT, 'tiff_ifd_truncated'
        tags = {}
        for i in range(count):
            entry = table[12 * i:12 * i + 12]
            tags[struct.unpack(u16, entry[:2])[0]] = (struct.unpack(u16, entry[2:4])[0], struct.unpack(u32, entry[4:8])[0], entry[8:12])
        for offsets_tag, counts_tag in ((273, 279), (324, 325)):
            if offsets_tag in tags and counts_tag in tags:
                kind, n, value = tags[offsets_tag]
                width = 2 if kind == 3 else 4
                fmt = u16 if width == 2 else u32
                if n * width <= 4:
                    starts = [struct.unpack(fmt, value[i * width:(i + 1) * width])[0] for i in range(n)]
                else:
                    pointer = struct.unpack(u32, value)[0]
                    raw = blob.read(pointer, min(n, 100000) * width)
                    if len(raw) < min(n, 100000) * width:
                        return SUSPECT, 'tiff_strip_table_out_of_file'
                    starts = [struct.unpack_from(fmt, raw, i * width)[0] for i in range(min(n, 100000))]
                if any(s >= blob.size for s in starts):
                    return SUSPECT, 'tiff_strip_offset_out_of_file'
        offset = struct.unpack(u32, table[12 * count:12 * count + 4])[0]
    return USABLE, 'tiff_ifd'


def check_pe(blob):
    head = blob.read(0, 4096)
    if head[:2] != b'MZ' or len(head) < 64:
        return SUSPECT, 'pe_mz'
    pe = struct.unpack_from('<I', head, 60)[0]
    header = blob.read(pe, 24)
    if header[:4] != b'PE\0\0':
        return SUSPECT, 'pe_signature'
    sections, optional = struct.unpack_from('<H', header, 6)[0], struct.unpack_from('<H', header, 20)[0]
    table = blob.read(pe + 24 + optional, 40 * sections)
    for i in range(sections):
        raw_size, raw_pointer = struct.unpack_from('<II', table, 40 * i + 16)
        if raw_pointer + raw_size > blob.size + 4096:
            return SUSPECT, 'pe_section_beyond_file'
    return USABLE, 'pe_sections'


def check_mp4(blob):
    position, kinds = 0, set()
    while position + 8 <= blob.size:
        size, kind = struct.unpack('>I4s', blob.read(position, 8))
        if size == 1:
            size = struct.unpack('>Q', blob.read(position + 8, 8))[0]
        elif size == 0:
            size = blob.size - position
        if size < 8 or position + size > blob.size or not (kind.isalnum() or kind in (b'free', b'skip')):
            return SUSPECT, 'mp4_box_tree'
        kinds.add(kind)
        position += size
    return (USABLE, 'mp4_box_tree') if b'moov' in kinds and b'mdat' in kinds else (SUSPECT, 'mp4_missing_moov_or_mdat')


def check_gif(blob):
    head = blob.read(0, 13)
    if head[:6] not in (b'GIF87a', b'GIF89a'):
        return SUSPECT, 'gif_header'
    position = 13 + (3 << ((head[10] & 7) + 1) if head[10] & 0x80 else 0)

    def sub_blocks(position):
        while True:
            length = blob.read(position, 1)
            if not length:
                return None
            position += 1 + length[0]
            if not length[0]:
                return position

    for _ in range(1_000_000):
        tag = blob.read(position, 1)
        if not tag:
            return SUSPECT, 'gif_truncated'
        if tag == b';':
            rest = blob.read(position + 1, 1 << 16).rstrip(b'\0')
            return USABLE, 'gif_block_structure' if not rest else 'gif_block_structure_trailing_data'
        if tag == b'!':
            position = sub_blocks(position + 2)
        elif tag == b',':
            descriptor = blob.read(position, 10)
            if len(descriptor) < 10:
                return SUSPECT, 'gif_truncated'
            position += 10 + (3 << ((descriptor[9] & 7) + 1) if descriptor[9] & 0x80 else 0) + 1
            position = sub_blocks(position)
        else:
            return SUSPECT, 'gif_bad_block'
        if position is None:
            return SUSPECT, 'gif_truncated'
    return SUSPECT, 'gif_too_many_blocks'


def check_sqlite(path):
    import contextlib
    uri = 'file:' + str(path).replace('\\\\?\\', '').replace('%', '%25').replace('?', '%3f').replace('#', '%23') + '?mode=ro&immutable=1'
    with contextlib.closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute('PRAGMA trusted_schema=OFF')
        return (USABLE, 'sqlite_quick_check') if db.execute('PRAGMA quick_check').fetchone()[0] == 'ok' else (SUSPECT, 'sqlite_quick_check')


def check_text(blob):
    sample = blob.read(0, 1 << 20) + blob.read(max(1 << 20, blob.size - (1 << 18)), 1 << 18)
    if sample[:2] in (b'\xff\xfe', b'\xfe\xff'):
        try:
            sample[2:len(sample) // 2 * 2].decode('utf-16')
            return USABLE, 'text_decodes_utf16'
        except UnicodeDecodeError:
            return SUSPECT, 'text_not_decodable'
    if b'\0' in sample:
        return SUSPECT, 'text_contains_binary'
    for encoding in ('utf-8', 'gb18030'):
        try:
            sample.decode(encoding)
            return USABLE, 'text_decodes_' + encoding
        except UnicodeDecodeError:
            continue
    return SUSPECT, 'text_not_decodable'


def all_zero(blob):
    return all(not piece.strip(b'\0') for _, piece in blob.chunks())


def grade(name, *, data=None, path=None, deep_limit=4 * 1024 ** 3):
    """Return (grade, detail). Pass ``data`` (whole file) or ``path``."""
    blob = Blob(data=data, path=path)
    try:
        return _grade(name, blob, path, deep_limit)
    except (OSError, ValueError, struct.error, zipfile.BadZipFile, sqlite3.DatabaseError, IndexError, EOFError,
            NotImplementedError, RuntimeError, zlib.error, OverflowError, MemoryError) as error:
        return SUSPECT, f'check_error:{type(error).__name__}'
    finally:
        blob.close()


def _grade(name, blob, path, deep_limit):
    lower = name.lower()
    ext = lower.rsplit('.', 1)[-1] if '.' in lower else ''
    if blob.size == 0:
        return USABLE, 'empty_file'
    if lower.startswith(('._', '~$')):
        return REVIEW, 'metadata_or_lock_file'
    head = blob.read(0, 4096)
    kind = detect(head)
    if not head.strip(b'\0'):
        if blob.size <= deep_limit and all_zero(blob):
            return SUSPECT, 'all_zero_content'
        return REVIEW, 'leading_zero_cluster'
    want = EXPECT.get(ext)
    if ext in ('db', 'sqlite', 'sqlite3') and kind == 'sqlite':
        if path is None:
            return REVIEW, 'sqlite_needs_file_check'
        return check_sqlite(path)
    if want and kind != want and not (want == 'zip' and kind == 'zip') and not (want == 'ole' and kind == 'ole'):
        if not (ext == 'db' and kind == 'ole'):
            return SUSPECT, f'header_mismatch(expected {want}, found {kind})'
    if blob.size > deep_limit and kind not in ('mp4',):
        return REVIEW, 'too_large_for_deep_check'
    if kind == 'jpg':
        return check_jpeg(blob)
    if kind == 'png':
        return check_png(blob)
    if kind == 'pdf':
        return check_pdf(blob)
    if kind == 'zip':
        return check_zip(blob)
    if kind == 'ole':
        return check_ole(blob)
    if kind == 'tif':
        return check_tif(blob)
    if kind == 'gif':
        return check_gif(blob)
    if kind == 'mz' and ext in PE:
        return check_pe(blob)
    if kind == 'mp4' and ext in MP4:
        return check_mp4(blob)
    if ext in TEXT:
        return check_text(blob)
    if want:
        return REVIEW, 'header_ok_no_deep_check'
    return REVIEW, 'no_format_check'


def is_thumbnail_cache(name):
    return name.lower() in THUMBNAIL_NAMES
