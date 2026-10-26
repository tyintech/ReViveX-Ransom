"""Parsers for raw NTFS evidence captured without any container mapping.

Pure functions over bytes: FILE records (1024-byte, NTFS 3.1 layout), INDX
index blocks, NTFS boot sectors, VHDX metadata tables and 16-byte file-start
signatures. Nothing here reads the source; callers pass captured bytes.
"""
from __future__ import annotations

import struct

MiB = 1024 * 1024
RECORD_SIZE = 1024
INDEX_BLOCK = 4096
MASK48 = (1 << 48) - 1
VHDX_BLOCK_SIZE_GUID = bytes.fromhex('3767a1ca36fa434db3b633f0aa44e76b')
VHDX_VIRTUAL_SIZE_GUID = bytes.fromhex('2442a52f1bcd7648b2115dbed83bf4b8')
VHDX_LOGICAL_SECTOR_GUID = bytes.fromhex('1dbf41816fa90947ba47f233a8faab5f')


def fixup_ok(data, offset, size):
    """Cheap in-place check of the update-sequence array (no copy)."""
    if offset + size > len(data):
        return False
    uo, uc = struct.unpack_from('<HH', data, offset + 4)
    if uc != size // 512 + 1 or uo < 40 or uo + uc * 2 > 512:
        return False
    seq = data[offset + uo:offset + uo + 2]
    return all(data[offset + i * 512 - 2:offset + i * 512] == seq for i in range(1, uc))


def apply_fixup(raw, size):
    raw = bytearray(raw[:size])
    if len(raw) < size:
        return None
    uo, uc = struct.unpack_from('<HH', raw, 4)
    if uc != size // 512 + 1 or uo < 40 or uo + uc * 2 > 512:
        return None
    seq = raw[uo:uo + 2]
    for i in range(1, uc):
        if raw[i * 512 - 2:i * 512] != seq:
            return None
        raw[i * 512 - 2:i * 512] = raw[uo + 2 * i:uo + 2 * i + 2]
    return raw


def decode_runs(record, position, length):
    """NTFS mapping pairs -> [[lcn or None (sparse), clusters], ...] or None."""
    offset = struct.unpack_from('<H', record, position + 32)[0]
    cursor, end, lcn, runs = position + offset, position + length, 0, []
    while cursor < end and record[cursor]:
        header = record[cursor]
        size_length, offset_length = header & 15, header >> 4
        if not size_length or cursor + 1 + size_length + offset_length > end:
            return None
        count = int.from_bytes(record[cursor + 1:cursor + 1 + size_length], 'little')
        if count <= 0:
            return None
        if offset_length:
            lcn += int.from_bytes(record[cursor + 1 + size_length:cursor + 1 + size_length + offset_length], 'little', signed=True)
            if lcn < 0:
                return None
            runs.append([lcn, count])
        else:
            runs.append([None, count])
        cursor += 1 + size_length + offset_length
    return runs


def _filename(value):
    if len(value) < 66 or 66 + value[64] * 2 > len(value):
        return None
    parent = struct.unpack_from('<Q', value)[0]
    name = value[66:66 + value[64] * 2].decode('utf-16le', 'replace')
    return [name, parent & MASK48, parent >> 48, value[65], struct.unpack_from('<Q', value, 16)[0]]


def parse_record(raw):
    """Parse a 1024-byte FILE record. Returns None when it is not a sane record.

    names: [name, parent_number, parent_sequence, namespace, modified_filetime]
    attrs: $DATA (0x80) and $INDEX_ALLOCATION (0xA0) attribute summaries.
    """
    record = apply_fixup(raw, RECORD_SIZE)
    if record is None or record[:4] != b'FILE':
        return None
    usa_offset = struct.unpack_from('<H', record, 4)[0]
    attr_offset, flags, used, allocated = struct.unpack_from('<HHII', record, 20)
    if usa_offset < 48 or allocated != RECORD_SIZE or not 56 <= attr_offset < used <= RECORD_SIZE:
        return None  # NTFS 3.0 records carry no self-number; not supported.
    lsn = struct.unpack_from('<Q', record, 8)[0]
    sequence = struct.unpack_from('<H', record, 16)[0]
    base_ref = struct.unpack_from('<Q', record, 32)[0]
    number = struct.unpack_from('<I', record, 44)[0]
    names, attrs, has_list, volume_name = [], [], False, None
    position = attr_offset
    while position + 16 <= used:
        kind, length = struct.unpack_from('<II', record, position)
        if kind == 0xFFFFFFFF:
            break
        if length < 16 or length % 8 or position + length > used:
            return None
        nonresident, name_length = record[position + 8], record[position + 9]
        name_offset, attr_flags = struct.unpack_from('<HH', record, position + 10)
        attr_name = record[position + name_offset:position + name_offset + name_length * 2].decode('utf-16le', 'replace') if name_length else ''
        if kind == 0x20:
            has_list = True
        if not nonresident and length >= 24:
            value_length, value_offset = struct.unpack_from('<IH', record, position + 16)
            value = bytes(record[position + value_offset:position + value_offset + value_length])
            if value_offset + value_length > length:
                return None
            if kind == 0x30:
                link = _filename(value)
                if link:
                    names.append(link)
            elif kind == 0x60 and value:
                volume_name = value.decode('utf-16le', 'replace')
            elif kind in (0x80, 0xA0):
                attrs.append(dict(t=kind, n=attr_name, nr=0, size=value_length, fl=attr_flags))
        elif nonresident and kind in (0x80, 0xA0) and length >= 64:
            svcn, evcn = struct.unpack_from('<QQ', record, position + 16)
            allocated_size, real, initialized = struct.unpack_from('<QQQ', record, position + 40)
            attrs.append(dict(t=kind, n=attr_name, nr=1, svcn=svcn, evcn=evcn, size=real, init=initialized,
                              fl=attr_flags, runs=decode_runs(record, position, length)))
        position += length
    result = dict(number=number, seq=sequence, lsn=lsn, base=base_ref & MASK48, base_seq=base_ref >> 48,
                  flags=flags, names=names, attrs=attrs, has_list=has_list)
    if volume_name is not None:
        result['volume_name'] = volume_name
    return result


def resident_data(raw):
    """Unnamed resident $DATA value of a captured record, or None."""
    record = apply_fixup(raw, RECORD_SIZE)
    if record is None:
        return None
    position, used = struct.unpack_from('<H', record, 20)[0], struct.unpack_from('<I', record, 24)[0]
    while position + 24 <= min(used, RECORD_SIZE):
        kind, length = struct.unpack_from('<II', record, position)
        if kind == 0xFFFFFFFF or length < 24:
            break
        if kind == 0x80 and not record[position + 8] and not record[position + 9]:
            value_length, value_offset = struct.unpack_from('<IH', record, position + 16)
            if value_offset + value_length > length:
                return None
            return bytes(record[position + value_offset:position + value_offset + value_length])
        position += length
    return None


def parse_indx(raw):
    """INDX block -> (vcn, [(child, child_seq, parent, parent_seq, namespace, name), ...]) or None."""
    block = apply_fixup(raw, INDEX_BLOCK)
    if block is None or block[:4] != b'INDX':
        return None
    vcn = struct.unpack_from('<Q', block, 16)[0]
    entries_offset, total = struct.unpack_from('<II', block, 24)
    position, end, entries = 24 + entries_offset, min(INDEX_BLOCK, 24 + total), []
    while position + 16 <= end:
        reference, entry_length, key_length, entry_flags = struct.unpack_from('<QHHI', block, position)
        if entry_length < 16 or entry_flags & 2 or position + entry_length > INDEX_BLOCK:
            break
        if key_length >= 66 and position + 16 + key_length <= INDEX_BLOCK:
            key = bytes(block[position + 16:position + 16 + key_length])
            link = _filename(key)
            if link:
                entries.append((reference & MASK48, reference >> 48, link[1], link[2], link[3], link[0]))
        position += entry_length
    return vcn, entries


def parse_boot(raw):
    """NTFS boot sector -> geometry dict, or None."""
    if len(raw) < 512 or raw[3:11] != b'NTFS    ' or raw[510:512] != b'\x55\xaa':
        return None
    sector, per_cluster = struct.unpack_from('<HB', raw, 11)
    if per_cluster > 0x80:
        per_cluster = 1 << (256 - per_cluster)
    if sector not in (512, 1024, 2048, 4096) or per_cluster not in tuple(1 << i for i in range(13)):  # up to 2 MiB clusters
        return None
    total, mft, mirror = struct.unpack_from('<QQQ', raw, 40)
    serial = struct.unpack_from('<Q', raw, 72)[0]
    return dict(cluster_size=sector * per_cluster, sector_size=sector, total_sectors=total,
                mft_lcn=mft, mirror_lcn=mirror, serial=serial)


def parse_vhdx_metadata(raw):
    """VHDX metadata table (signature 'metadata') -> block/virtual/sector sizes."""
    if raw[:8] != b'metadata' or len(raw) < 64:
        return None
    count = struct.unpack_from('<H', raw, 10)[0]
    found = {}
    for i in range(min(count, 2047)):
        entry = raw[32 + 32 * i:64 + 32 * i]
        if len(entry) < 32:
            break
        guid, offset, length = entry[:16], *struct.unpack_from('<II', entry, 16)
        value = raw[offset:offset + length] if offset + length <= len(raw) else b''
        if guid == VHDX_BLOCK_SIZE_GUID and len(value) >= 4:
            found['block_size'] = struct.unpack_from('<I', value)[0]
        elif guid == VHDX_VIRTUAL_SIZE_GUID and len(value) >= 8:
            found['virtual_size'] = struct.unpack_from('<Q', value)[0]
        elif guid == VHDX_LOGICAL_SECTOR_GUID and len(value) >= 4:
            found['logical_sector_size'] = struct.unpack_from('<I', value)[0]
    block = found.get('block_size')
    if not block or block % MiB or block & (block - 1) or block > 256 * MiB:
        return None
    return found


# --- file-start signatures ----------------------------------------------------
TYPES = ('jpg', 'png', 'pdf', 'zip', 'ole', 'riff', 'gif', 'mz', 'tif', '7z', 'rar', 'psd', 'mp4', 'asf', 'mkv',
         'dwg', 'cab', 'gz', 'rtf', 'sqlite', 'bmp', 'xml', 'flac', 'ogg', 'id3', 'chm')
TYPE_CODE = {name: index + 1 for index, name in enumerate(TYPES)}
# Leading bytes captured by the evidence scan; classify() decides the type.
MAGICS = (b'\xff\xd8\xff', b'\x89PNG', b'%PDF', b'PK\x03\x04', b'\xd0\xcf\x11\xe0', b'RIFF', b'GIF8', b'MZ',
          b'II*\x00', b'MM\x00*', b'7z\xbc\xaf', b'Rar!', b'ID3', b'SQLite f', b'BM', b'<?xml', b'\x1f\x8b', b'8BPS',
          b'{\\rtf', b'\x00\x00\x00\x18ftyp', b'\x00\x00\x00\x1cftyp', b'\x00\x00\x00\x20ftyp', b'\x00\x00\x00\x14ftyp',
          b'MSCF', b'ITSF', b'\x30\x26\xb2\x75', b'fLaC', b'OggS', b'\x1aE\xdf\xa3', b'AC10')


def classify(head):
    head = bytes(head)
    if head[:3] == b'\xff\xd8\xff': return 'jpg'
    if head[:4] == b'\x89PNG': return 'png'
    if head[:4] == b'%PDF': return 'pdf'
    if head[:4] == b'PK\x03\x04': return 'zip'
    if head[:4] == b'\xd0\xcf\x11\xe0': return 'ole'
    if head[:4] == b'RIFF': return 'riff'
    if head[:4] == b'GIF8': return 'gif'
    if head[:4] in (b'II*\x00', b'MM\x00*'): return 'tif'
    if head[:4] == b'7z\xbc\xaf': return '7z'
    if head[:4] == b'Rar!': return 'rar'
    if head[:4] == b'8BPS': return 'psd'
    if head[4:8] == b'ftyp': return 'mp4'
    if head[:4] == b'0&\xb2u': return 'asf'
    if head[:4] == b'\x1aE\xdf\xa3': return 'mkv'
    if head[:4] == b'AC10': return 'dwg'
    if head[:4] == b'MSCF': return 'cab'
    if head[:5] == b'{\\rtf': return 'rtf'
    if head[:8] == b'SQLite f': return 'sqlite'
    if head[:4] == b'fLaC': return 'flac'
    if head[:4] == b'OggS': return 'ogg'
    if head[:4] == b'ITSF': return 'chm'
    if head[:2] == b'\x1f\x8b': return 'gz'
    if head[:2] == b'MZ': return 'mz'
    return None


_EXTENSIONS = dict(
    jpg='jpg jpeg jfif jpe', png='png', pdf='pdf ai', zip='zip docx xlsx pptx jar apk odt ods odp vsdx xps epub kmz dwfx',
    ole='doc xls ppt msg vsd pub msi mpp', riff='avi wav webp', gif='gif', mz='exe dll sys ocx cpl scr drv efi mui',
    tif='tif tiff nef cr2 dng arw orf', rar='rar', psd='psd', mp4='mp4 mov m4a m4v 3gp heic heif',
    asf='wmv wma asf', mkv='mkv webm', dwg='dwg', cab='cab', gz='gz tgz', rtf='rtf', sqlite='sqlite sqlite3',
    flac='flac', ogg='ogg oga', chm='chm', **{'7z': '7z'})
EXTENSION_TYPE = {ext: kind for kind, values in _EXTENSIONS.items() for ext in values.split()}
IMAGE_EXTENSIONS = {'vhd', 'vhdx', 'avhdx', 'vmdk', 'vdi', 'img', 'wim', 'bak', 'tib', 'gho', 'v2i', 'iso', 'esd',
                    'vbk', 'vib', 'qcow2', 'raw', 'dd'}


def extension(name):
    return name.rsplit('.', 1)[-1].lower() if name and '.' in name else ''


def expected_type(name):
    return EXTENSION_TYPE.get(extension(name))


def primary_name(names):
    """Prefer Win32 / Win32+DOS names over POSIX and DOS-only short names."""
    if not names:
        return None
    return sorted(names, key=lambda n: ({1: 0, 3: 0, 0: 1, 2: 2}.get(n[3], 3), n[0]))[0]


def data_attribute(attrs):
    """Return ('resident', size) / ('nonresident', [parts]) for the unnamed $DATA."""
    parts = [a for a in attrs if a['t'] == 0x80 and not a['n']]
    if any(not a['nr'] for a in parts):
        return 'resident', next(a['size'] for a in parts if not a['nr'])
    return ('nonresident', parts) if parts else (None, None)


def first_data_lcn(attrs):
    for attr in attrs:
        if attr['t'] == 0x80 and not attr['n'] and attr['nr'] and attr.get('svcn') == 0 and attr.get('runs'):
            first = attr['runs'][0][0]
            return first if first else None
    return None
