"""Read-only logical NTFS file recovery from a raw disk/partition or validated VHDX.

This is file salvage, not decryption, disk repair, or bootable VM reconstruction.
Dissect 3.16 decodes validated attribute runlists and streams. Metadata is bounded
and checked here before its decoder is called; extension records are not guessed.
"""
import argparse
import hashlib
import io
import json
import os
import struct
import sqlite3
import uuid
import zlib
from pathlib import Path

from dissect.ntfs.attr import AttributeHeader
from dissect.util.stream import RunlistStream
from recover_vhdx_resident import parse_record, attributes, file_names, safe_name, portable_basename


class UnsupportedNTFS(ValueError):
    pass


class Cancelled(Exception):
    pass


class RawReader:
    def __init__(self, path, damaged_ranges=(), sector_size=512):
        self.fh = open(path, 'rb')
        self._stat = os.fstat(self.fh.fileno())
        self.size = self._stat.st_size
        self.sector_size = sector_size
        self.damaged_ranges = list(damaged_ranges)
        self.evidence = {'format': 'raw', 'logical_size': self.size}

    def read_at(self, offset, length):
        now = os.fstat(self.fh.fileno())
        if (now.st_size, now.st_mtime_ns, now.st_ctime_ns) != (self._stat.st_size, self._stat.st_mtime_ns, self._stat.st_ctime_ns):
            raise OSError('Source changed during recovery')
        if offset < 0 or length < 0 or offset + length > self.size:
            raise OSError('Read outside source bounds')
        if any(offset < end and offset + length > start for start, end in self.damaged_ranges):
            raise OSError(f'Known damaged/encrypted physical range at {offset}:{offset + length}')
        self.fh.seek(offset)
        data = self.fh.read(length)
        if len(data) != length:
            raise OSError('Short source read')
        return data

    def close(self):
        self.fh.close()


class Volume(io.RawIOBase):
    def __init__(self, disk, offset, size):
        self.disk, self.offset, self.size, self.pos = disk, offset, size, 0

    def seek(self, offset, whence=0):
        pos = offset if whence == 0 else self.pos + offset if whence == 1 else self.size + offset if whence == 2 else -1
        if pos < 0:
            raise ValueError('Invalid seek')
        self.pos = pos
        return pos

    def tell(self):
        return self.pos

    def read(self, length=-1):
        if length < 0:
            length = max(0, self.size - self.pos)
        length = min(length, max(0, self.size - self.pos))
        result = self.disk.read_at(self.offset + self.pos, length)
        self.pos += len(result)
        return result

    def readable(self):
        return True

    def seekable(self):
        return True


def read_at(stream, offset, length):
    stream.seek(offset)
    data = stream.read(length)
    if len(data) != length:
        raise OSError(f'Short logical read at {offset}, wanted {length}, got {len(data)}')
    return data


def partitions(disk):
    """Bounded NTFS superfloppy / primary MBR / CRC-checked GPT enumeration."""
    head = disk.read_at(0, 512)
    if head[3:11] == b'NTFS    ':
        return [{'offset': 0, 'size': disk.size, 'scheme': 'superfloppy'}]
    if head[510:512] != b'\x55\xaa':
        raise ValueError('No NTFS boot sector or valid partition-table signature')
    sector = disk.sector_size
    entries = [head[446 + i * 16:462 + i * 16] for i in range(4)]
    result = []
    if any(e[4] == 0xee for e in entries):
        header = disk.read_at(sector, sector)
        if header[:8] != b'EFI PART':
            raise ValueError('Protective MBR without GPT header; backup GPT fallback unsupported')
        revision, size, crc = struct.unpack_from('<III', header, 8)
        if revision != 0x10000 or not 92 <= size <= sector or header[20:24] != bytes(4):
            raise ValueError('Invalid GPT header')
        check = bytearray(header[:size]); check[16:20] = bytes(4)
        if zlib.crc32(check) & 0xffffffff != crc:
            raise ValueError('GPT header CRC mismatch; backup GPT fallback unsupported')
        current, backup, first, last = struct.unpack_from('<QQQQ', header, 24)
        lba, count, entry_size, array_crc = struct.unpack_from('<QIII', header, 72)
        sectors = disk.size // sector
        if current != 1 or backup != sectors - 1 or not 2 <= first <= last < backup:
            raise ValueError('Invalid GPT disk bounds')
        if not 1 <= count <= 16384 or entry_size < 128 or entry_size % 128 or count * entry_size > 16 * 1024 * 1024:
            raise ValueError('Invalid or oversized GPT entry array')
        if lba < 2 or lba * sector + count * entry_size > first * sector:
            raise ValueError('GPT entry array overlaps usable data')
        array = disk.read_at(lba * sector, count * entry_size)
        if zlib.crc32(array) & 0xffffffff != array_crc:
            raise ValueError('GPT partition-array CRC mismatch')
        for i in range(count):
            entry = array[i * entry_size:(i + 1) * entry_size]
            if entry[:16] == bytes(16):
                continue
            start, end = struct.unpack_from('<QQ', entry, 32)
            if not first <= start <= end <= last:
                raise ValueError('GPT partition outside usable disk')
            result.append({'offset': start * sector, 'size': (end - start + 1) * sector,
                           'scheme': 'gpt', 'partition_guid': str(uuid.UUID(bytes_le=entry[16:32])),
                           'disk_guid': str(uuid.UUID(bytes_le=header[56:72])), 'partition_index': i + 1})
    else:
        for i, entry in enumerate(entries):
            kind = entry[4]
            if not kind:
                continue
            if entry[0] not in (0, 0x80):
                raise ValueError('Invalid MBR boot flag')
            start, count = struct.unpack_from('<II', entry, 8)
            if not start or not count or (start + count) * sector > disk.size:
                raise ValueError('MBR partition outside disk')
            result.append({'offset': start * sector, 'size': count * sector, 'scheme': 'mbr',
                           'partition_type': kind, 'partition_index': i + 1,
                           'unsupported': 'extended_partition_chain' if kind in (5, 15, 0x85) else None})
    intervals = sorted((p['offset'], p['offset'] + p['size']) for p in result)
    if any(a[1] > b[0] for a, b in zip(intervals, intervals[1:])):
        raise ValueError('Overlapping partitions')
    if not result:
        raise ValueError('No partitions found')
    return result


def parse_boot(raw, bound):
    if len(raw) < 512 or raw[3:11] != b'NTFS    ' or raw[510:512] != b'\x55\xaa':
        raise ValueError('Invalid NTFS boot signature')
    sector, spc = struct.unpack_from('<HB', raw, 11)
    if sector != 512:
        raise UnsupportedNTFS(f'NTFS sector size {sector} unsupported; only 512-byte NTFS sectors tested')
    if not spc or spc & (spc - 1) or spc > 128:
        raise ValueError('Invalid NTFS cluster geometry')
    if raw[14:21] != bytes(7) or raw[22:24] != bytes(2) or raw[32:36] != bytes(4):
        raise ValueError('Invalid NTFS reserved BPB fields')
    total, mft, mirror = struct.unpack_from('<QQQ', raw, 40)
    cluster = sector * spc
    code = struct.unpack_from('<b', raw, 64)[0]
    record_size = 1 << -code if -20 <= code < 0 else code * cluster if code > 0 else 0
    if record_size != 1024:
        raise UnsupportedNTFS(f'NTFS FILE record size {record_size} unsupported; only 1024-byte records tested')
    if total < 16 or total * sector > bound or not 0 < mft * cluster < total * sector - record_size or not 0 < mirror * cluster < total * sector - record_size:
        raise ValueError('NTFS volume or MFT bounds invalid')
    return {'sector_size': sector, 'cluster_size': cluster, 'record_size': record_size,
            'size': total * sector, 'mft_lcn': mft, 'mirror_lcn': mirror,
            'serial': f'{struct.unpack_from("<Q", raw, 72)[0]:016x}'}


def boot_for(volume):
    try:
        primary = read_at(volume, 0, 512)
        boot = parse_boot(primary, volume.size)
        boot['boot_source'] = 'primary'
        return boot
    except UnsupportedNTFS:
        raise
    except (ValueError, OSError) as error:
        # Only a known exact partition boundary supplies a trustworthy backup location.
        backup = read_at(volume, volume.size - 512, 512)
        boot = parse_boot(backup, volume.size)
        if boot['size'] not in (volume.size, volume.size - boot['sector_size']):
            raise ValueError('Backup NTFS boot does not match exact partition bounds') from error
        boot.update(boot_source='validated_backup_at_partition_end', primary_boot_error=str(error))
        return boot


def decoded_attributes(record):
    result = []
    for offset, kind, raw in attributes(record.data):
        header = AttributeHeader.from_bytes(raw + bytes(max(0, 80 - len(raw))))
        # Never let a nonresident name overlap the runlist.
        result.append({'offset': offset, 'kind': kind, 'raw': raw, 'header': header,
                       'id': struct.unpack_from('<H', raw, 14)[0], 'name': header.name})
    return result


def stream_for(attr, volume, boot):
    """Strict run coverage preflight followed by Dissect's runlist reader."""
    raw, header = attr['raw'], attr['header']
    if header.flags & ~0xc0ff:
        raise UnsupportedNTFS('Unknown NTFS attribute flags unsupported')
    if header.flags & 0x4000:
        raise UnsupportedNTFS('EFS encrypted stream unsupported')
    if header.flags & 0x00ff:
        raise UnsupportedNTFS('NTFS compressed stream unsupported')
    if header.resident:
        return header.open(), header.size, {'resident': True, 'initialized_size': header.size}
    first, last, mapping = struct.unpack_from('<QQH', raw, 16)
    compression = struct.unpack_from('<H', raw, 34)[0]
    allocated, size, initialized = struct.unpack_from('<QQQ', raw, 40)
    name_end = struct.unpack_from('<H', raw, 10)[0] + raw[9] * 2 if raw[9] else 0
    if compression and not (header.flags & 0x8000 and compression == 4):
        raise UnsupportedNTFS('Unsupported NTFS compression unit')
    if first:
        raise UnsupportedNTFS('Extension stream VCN requires ATTRIBUTE_LIST resolution')
    minimum = 72 if header.flags & 0x8000 else 64
    if not minimum <= mapping < len(raw) or (raw[9] and struct.unpack_from('<H', raw, 10)[0] < minimum) or mapping < name_end or initialized > size or size > volume.size:
        raise ValueError('Invalid nonresident attribute bounds')
    cursor, lcn, runs = mapping, 0, []
    while True:
        if cursor >= len(raw):
            raise ValueError('Unterminated mapping pairs')
        code = raw[cursor]; cursor += 1
        if not code:
            break
        n, d = code & 15, code >> 4
        if not 1 <= n <= 8 or d > 8 or cursor + n + d > len(raw):
            raise ValueError('Invalid mapping-pair widths')
        count = int.from_bytes(raw[cursor:cursor + n], 'little'); cursor += n
        if not count:
            raise ValueError('Zero-length mapping pair')
        location = None
        if d:
            lcn += int.from_bytes(raw[cursor:cursor + d], 'little', signed=True)
            location = lcn
            if lcn < 0 or (lcn + count) * boot['cluster_size'] > volume.size:
                raise ValueError('Data run outside logical volume')
        cursor += d
        runs.append((location, count))
    clusters = sum(n for _, n in runs)
    if not runs and last == (1 << 64) - 1 and size == initialized == allocated == 0:
        if header.flags & 0x8000 and struct.unpack_from('<Q', raw, 64)[0] != 0:
            raise ValueError('Empty sparse stream has nonzero physical allocation')
        return io.BytesIO(), 0, {'resident': False, 'runs': [], 'initialized_size': 0,
                                'sparse': bool(header.flags & 0x8000), 'allocated_size': 0,
                                'uninitialized_tail_zero_bytes': 0}
    if not runs or clusters != last + 1 or size > clusters * boot['cluster_size']:
        raise ValueError('Runlist does not cover declared VCN/data size')
    if any(lcn is None for lcn, _ in runs) and not header.flags & 0x8000:
        raise ValueError('Sparse run without sparse attribute flag')
    physical = sorted((lcn, lcn + count) for lcn, count in runs if lcn is not None)
    if any(a[1] > b[0] for a, b in zip(physical, physical[1:])):
        raise ValueError('Overlapping physical data runs')
    if not header.flags & 0x8000 and allocated != sum(count for lcn, count in runs if lcn is not None) * boot['cluster_size']:
        raise ValueError('Allocated length disagrees with physical run coverage')
    if header.flags & 0x8000:
        physical_size = struct.unpack_from('<Q', raw, 64)[0]
        if physical_size != sum(count for lcn, count in runs if lcn is not None) * boot['cluster_size']:
            raise ValueError('Sparse physical allocation disagrees with runs')
        if allocated != clusters * boot['cluster_size']:
            raise ValueError('Sparse logical allocation disagrees with VCN coverage')
    if header.dataruns() != runs:
        raise ValueError('Dissect runlist decode disagrees with unsigned bounds validation')
    return RunlistStream(volume, runs, initialized, boot['cluster_size'], align=1), size, {
        'resident': False, 'runs': [{'lcn': lcn, 'clusters': count} for lcn, count in runs],
        'initialized_size': initialized, 'sparse': any(lcn is None for lcn, _ in runs),
        'allocated_size': allocated, 'uninitialized_tail_zero_bytes': size - initialized}


def record_info(record, number, attrs):
    return {'record_number': number, 'sequence': int(record.header.SequenceNumber),
            'in_use': bool(record.header.Flags & 1), 'directory': bool(record.header.Flags & 2),
            'base_record_reference': struct.unpack_from('<Q', record.data, 32)[0],
            'file_names': file_names(record),
            'has_attribute_list': any(a['kind'] == 0x20 for a in attrs),
            'has_reparse_point': any(a['kind'] == 0xc0 for a in attrs)}


def verified_paths(info, records, max_depth=128, max_paths=256):
    """Prove allocated parent/sequence chains in this logical volume, not content authenticity."""
    def walk(item, visited):
        number = item['record_number']
        if number in visited or len(visited) >= max_depth:
            raise ValueError('parent_cycle_or_depth_limit')
        if not item['in_use'] or item['base_record_reference'] or item['has_attribute_list'] or item['has_reparse_point']:
            raise ValueError('unresolved_or_nonlive_parent')
        if number == 5:
            if not item['directory']:
                raise ValueError('root_not_directory')
            return ['']
        paths = []
        if not item['file_names']:
            raise ValueError('missing_file_name')
        for link in item['file_names']:
            name = link['name']
            if name in ('', '.', '..') or any(c in name for c in '/\\\x00') or any(ord(c) < 32 for c in name):
                raise ValueError('unsafe_metadata_name')
            parent = records.get(link['parent_record'])
            if not parent or not parent['directory'] or not link['parent_sequence'] or parent['sequence'] != link['parent_sequence']:
                raise ValueError('missing_parent_or_stale_sequence')
            for prefix in walk(parent, visited | {number}):
                paths.append(prefix + '/' + name)
                if len(paths) > max_paths:
                    raise ValueError('path_expansion_limit')
        return paths
    try:
        paths = walk(info, set())
        return {'paths': paths, 'path_status': 'verified_mft_parent_sequence_chain',
                'path_limitations': 'Metadata chain only; directory indexes and content authenticity are not verified.'}
    except ValueError as error:
        return {'paths': [], 'path_status': 'unknown', 'path_error': str(error)}


def fresh_output(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink output ancestors are forbidden')
    if path.exists():
        raise ValueError('Output directory must be new')
    path.mkdir(parents=True, mode=0o700)
    return path


def load_logical_record(raw, number):
    record, _ = parse_record(raw)
    attrs = decoded_attributes(record)
    meta = record_info(record, number, attrs)
    # The on-disk number was added in NTFS 3.1. Nonzero disagreement is corruption.
    stored_number = struct.unpack_from('<I', record.data, 44)[0]
    if stored_number and stored_number != number:
        raise ValueError('MFT record number disagrees with logical slot')
    return record, attrs, meta

def _bootstrap_mft(volume, boot, offset):
    record, attrs, meta = load_logical_record(read_at(volume, offset, 1024), 0)
    if not meta['in_use'] or meta['base_record_reference'] or meta['has_attribute_list']:
        raise UnsupportedNTFS('MFT bootstrap extension/ATTRIBUTE_LIST unsupported')
    if not any(n['name'] == '$MFT' for n in meta['file_names']):
        raise ValueError('MFT bootstrap is not named $MFT')
    streams = [a for a in attrs if a['kind'] == 0x80 and not a['name']]
    if len(streams) != 1:
        raise UnsupportedNTFS('MFT requires exactly one base DATA runlist')
    stream, length, evidence = stream_for(streams[0], volume, boot)
    if evidence['resident'] or evidence.get('sparse') or evidence['initialized_size'] != length or length < 1024 or length % 1024:
        raise ValueError('Invalid MFT stream geometry')
    if evidence['runs'][0]['lcn'] != boot['mft_lcn']:
        raise ValueError('MFT runlist does not start at boot MFT location')
    return stream, length, evidence

def open_mft(volume, boot):
    """Return (stream, size, run evidence, source evidence); callers may resume by record slot."""
    volume.size = boot['size']
    try:
        stream, size, evidence = _bootstrap_mft(volume, boot, boot['mft_lcn'] * boot['cluster_size'])
        return stream, size, evidence, {'mft_source': 'primary'}
    except UnsupportedNTFS:
        raise
    except (ValueError, OSError) as error:
        stream, size, evidence = _bootstrap_mft(volume, boot, boot['mirror_lcn'] * boot['cluster_size'])
        return stream, size, evidence, {'mft_source': 'validated_mirror_bootstrap', 'primary_mft_error': str(error)}


def deserialize_attribute(data):
    """Restore an already bounded serialized attribute for stream_for preflight."""
    raw = bytes.fromhex(data['raw_hex'])
    if len(raw) > 1024:
        raise ValueError('Serialized attribute too large')
    result = {key: value for key, value in data.items() if key != 'raw_hex'}
    result['raw'] = raw
    result['header'] = AttributeHeader.from_bytes(raw + bytes(max(0, 80 - len(raw))))
    return result


def serialize_attribute(attr):
    return {key: attr[key] for key in ('offset', 'kind', 'id', 'name')} | {'raw_hex': attr['raw'].hex()}


class MetadataStore:
    """Disk-backed MFT metadata and extraction queue; no whole MFT kept in RAM."""
    def __init__(self, path):
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('CREATE TABLE records (number INTEGER PRIMARY KEY, metadata TEXT NOT NULL, raw BLOB, pending INTEGER NOT NULL)')

    def add(self, number, meta, raw, pending):
        self.db.execute('INSERT INTO records VALUES (?,?,?,?)', (number, json.dumps(meta), raw, int(pending)))

    def get(self, number):
        row = self.db.execute('SELECT metadata FROM records WHERE number=?', (number,)).fetchone()
        return json.loads(row[0]) if row else None

    def values(self):
        for row in self.db.execute('SELECT metadata FROM records ORDER BY number'):
            yield json.loads(row[0])

    def pending(self):
        self.db.commit()
        for row in self.db.execute('SELECT metadata,raw FROM records WHERE pending=1 ORDER BY number'):
            record, _ = parse_record(row[1])
            yield json.loads(row[0]), [a for a in decoded_attributes(record) if a['kind'] == 0x80]

    def close(self):
        self.db.commit()
        self.db.close()


def recover(source, output, *, source_format='auto', damaged_ranges=(), max_records=100000,
            max_file_bytes=1024**4, max_total_bytes=1024**4, chunk_size=1024**2,
            cancel=None, progress=None, partition_offset=None, partition_size=None,
            raw_sector_size=512, include_system=False, metadata_only=False, allow_partial_bat=False):
    """Export into a new directory. Limits/corruption never imply complete recovery."""
    if min(max_records, max_file_bytes, max_total_bytes, chunk_size) <= 0 or chunk_size > 16 * 1024**2:
        raise ValueError('Positive bounds required; chunk size must be <=16 MiB')
    if source_format not in ('auto', 'raw', 'vhdx') or raw_sector_size not in (512, 4096):
        raise ValueError('Invalid source format or raw sector size')
    for start, end in damaged_ranges:
        if start < 0 or end <= start:
            raise ValueError('Damaged ranges must be nonempty nonnegative half-open intervals')
    source = Path(source)
    before = source.stat()
    with source.open('rb') as fh:
        signature = fh.read(8)
    is_vhdx = source_format == 'vhdx' or source_format == 'auto' and signature == b'vhdxfile'
    if allow_partial_bat and not is_vhdx:
        raise ValueError('--allow-partial-bat applies only to VHDX sources')
    output = fresh_output(output)
    report = {'schema': 'revivex.ntfs-logical', 'schema_version': 1, 'source': str(source.absolute()),
              'source_size': before.st_size, 'status': 'partial', 'scan_status': 'running',
              'completeness': 'unknown', 'metadata_only': metadata_only, 'allow_partial_bat': bool(allow_partial_bat), 'files': [], 'directories': [], 'volumes': [], 'errors': [],
              'counts': {'recovered_streams': 0, 'partial_streams': 0, 'unsupported_streams': 0,
                         'corrupt_records': 0, 'exported_bytes': 0},
              'capabilities': {'source_access': 'read_only', 'nonresident_stream_export': True,
                               'resident_stream_export': True, 'decryption': False},
              'limitations': ['File salvage only; does not repair a VHDX or restore a bootable VM.',
                  'Hashes verify exported bytes, not original-content authenticity.',
                  'Aggregate completeness is unknown; deleted files, metadata extensions, EFS, compression and reparse points are unsupported.',
                  'Only 512-byte NTFS sectors and 1024-byte FILE records are supported.',
                  'Original names/links are provenance; exports use collision-safe flat names.',
                  'Never execute recovered payloads before malware review.'],
              'damaged_physical_ranges': list(damaged_ranges)}
    disk = None
    def checkpoint():
        if cancel and cancel():
            raise Cancelled('Cancelled by caller')
    try:
        checkpoint()
        if is_vhdx:
            from revivex_vhdx import VHDXReader
            disk = VHDXReader(source, damaged_ranges=damaged_ranges, allow_partial_bat=allow_partial_bat)
        else:
            disk = RawReader(source, damaged_ranges, raw_sector_size)
        report['source_mapping'] = disk.evidence
        if disk.evidence.get('partial_bat'):
            report['limitations'].append('Opt-in partial BAT salvage: faulty mappings remain unreadable; logical mapping is incomplete.')
        if partition_offset is not None:
            if partition_offset < 0 or partition_offset >= disk.size:
                raise ValueError('Explicit partition offset outside disk')
            size = partition_size if partition_size is not None else disk.size - partition_offset
            if size <= 0 or partition_offset + size > disk.size:
                raise ValueError('Explicit partition size outside disk')
            parts = [{'offset': partition_offset, 'size': size, 'scheme': 'explicit'}]
        else:
            if partition_size is not None:
                raise ValueError('--partition-size requires --partition-offset')
            parts = partitions(disk)
        for volume_index, part in enumerate(parts):
            checkpoint()
            info = dict(part, volume_index=volume_index, status='partial', errors=[])
            report['volumes'].append(info)
            records = None
            try:
                if part.get('unsupported'):
                    raise UnsupportedNTFS(part['unsupported'])
                volume = Volume(disk, part['offset'], part['size'])
                boot = boot_for(volume)
                volume.size = boot['size']
                info.update(boot)
                identity = f"ntfs-{boot['serial']}-{part['offset']:x}"
                info['volume_id'] = identity
                mft, mft_size, mft_evidence, source_evidence = open_mft(volume, boot)
                info.update(source_evidence)
                info['mft'] = mft_evidence
                records = MetadataStore(output / f'ntfs_records_{volume_index}.sqlite')
                info['metadata_index'] = f'ntfs_records_{volume_index}.sqlite'
                count = mft_size // 1024
                if count > max_records:
                    info['errors'].append(f'MFT record limit reached: {max_records}/{count}')
                for number in range(min(count, max_records)):
                    checkpoint()
                    if progress and number % 128 == 0:
                        progress({'phase': 'ntfs_metadata', 'records_examined': number, 'record_limit': min(count, max_records)})
                    try:
                        raw = read_at(mft, number * 1024, 1024)
                        if raw == bytes(1024):
                            continue
                        record, attrs, meta = load_logical_record(raw, number)
                        eligible = (meta['in_use'] and not meta['directory'] and not meta['base_record_reference']
                                    and not meta['has_attribute_list'] and not meta['has_reparse_point']
                                    and (number >= 16 or include_system))
                        records.add(number, meta, raw, eligible)
                        if not meta['in_use']:
                            report['files'].append(dict(meta, volume_id=identity, status='unsupported', reason='deleted_record_stale_allocation'))
                            continue
                        if meta['base_record_reference'] or meta['has_attribute_list'] or meta['has_reparse_point']:
                            report['files'].append(dict(meta, volume_id=identity, status='unsupported', reason='extension_attribute_list_or_reparse_unsupported'))
                            report['counts']['unsupported_streams'] += 1
                            continue
                        if meta['directory'] or number < 16 and not include_system:
                            continue
                        # Eligible raw records are queued in SQLite, not retained in RAM.
                    except (ValueError, OSError, EOFError, IndexError, struct.error) as error:
                        report['counts']['corrupt_records'] += 1
                        report['files'].append({'volume_id': identity, 'record_number': number, 'status': 'corrupt', 'reason': str(error)})
                info['records_examined'] = min(count, max_records)
                for directory in records.values():
                    if directory['directory']:
                        directory_paths = verified_paths(directory, records)
                        report['directories'].append(dict(directory, volume_id=identity, status='directory',
                            relative_path=directory_paths['paths'][0].lstrip('/') if directory_paths['paths'] else None,
                            path_reliability='logical_verified' if directory_paths['paths'] else 'unknown', **directory_paths))
                for meta, streams in records.pending():
                    checkpoint()
                    paths = verified_paths(meta, records)
                    paths['relative_path'] = paths['paths'][0].lstrip('/') if paths['paths'] else None
                    paths['path_reliability'] = 'logical_verified' if paths['paths'] else 'unknown'
                    if not streams:
                        report['files'].append(dict(meta, volume_id=identity, status='unsupported', reason='missing_DATA_stream', **paths))
                    duplicates = {a['name'] for a in streams if sum(b['name'] == a['name'] for b in streams) > 1}
                    for stream_index, attr in enumerate(streams):
                        checkpoint()
                        row = dict(meta, name=meta['file_names'][0]['name'] if meta['file_names'] else 'unnamed', volume_id=identity, stream_name=attr['name'], attribute_id=attr['id'],
                                   attribute_offset=attr['offset'], status='pending', **paths)
                        report['files'].append(row)
                        destination = None
                        try:
                            if attr['name'] in duplicates:
                                raise UnsupportedNTFS('Duplicate DATA stream names require extent resolution')
                            stream, length, evidence = stream_for(attr, volume, boot)
                            row.update(evidence, expected_size=length)
                            if metadata_only:
                                row.update(status='indexed', content_authenticity='unknown',
                                    source_descriptor={'volume_offset': part['offset'], 'volume_size': boot['size'],
                                        'mft_record': meta['record_number'], 'sequence': meta['sequence'],
                                        'attribute_id': attr['id'], 'attribute_offset': attr['offset'],
                                        'stream_name': attr['name']})
                                continue
                            if length > max_file_bytes or report['counts']['exported_bytes'] + length > max_total_bytes:
                                raise UnsupportedNTFS('Configured export byte limit')
                            name = meta['file_names'][0]['name'] if meta['file_names'] else 'unnamed'
                            leaf = f"v{volume_index}_r{meta['record_number']}_s{meta['sequence']}_a{stream_index}_{safe_name(name)}"
                            if attr['name']:
                                leaf += '__' + safe_name(attr['name'])[:40]
                            leaf = portable_basename(leaf)
                            destination = output / leaf
                            sha, crc, written = hashlib.sha256(), 0, 0
                            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
                            with os.fdopen(os.open(destination, flags, 0o600), 'wb') as target:
                                try:
                                    while written < length:
                                        checkpoint()
                                        amount = min(chunk_size, length - written)
                                        initialized = evidence['initialized_size']
                                        if written < initialized:
                                            amount = min(amount, initialized - written)
                                            chunk = stream.read(amount)
                                            if len(chunk) != amount:
                                                raise OSError('Short NTFS stream read')
                                        else:
                                            chunk = bytes(amount)  # NTFS initialized-size metadata explicitly defines this zero tail.
                                        target.write(chunk)
                                        sha.update(chunk); crc = zlib.crc32(chunk, crc)
                                        written += len(chunk)
                                        report['counts']['exported_bytes'] += len(chunk)
                                    target.flush(); os.fsync(target.fileno())
                                finally:
                                    row.update(output=leaf, size=written, sha256=sha.hexdigest(), crc32=f'{crc & 0xffffffff:08x}')
                            row.update(status='recovered', integrity='exported_bytes_only', content_authenticity='unknown')
                            report['counts']['recovered_streams'] += 1
                        except (Cancelled, KeyboardInterrupt):
                            row.update(status='partial', reason='cancelled')
                            report['counts']['partial_streams'] += 1
                            raise
                        except UnsupportedNTFS as error:
                            row.update(status='unsupported', reason=str(error))
                            report['counts']['unsupported_streams'] += 1
                        except (ValueError, OSError, EOFError, IndexError, struct.error) as error:
                            row.update(status='partial' if destination is not None else 'corrupt', reason=str(error))
                            report['counts']['partial_streams'] += 1
                        if progress:
                            progress({'phase': 'ntfs_export', **report['counts']})
                info['scan_status'] = 'finished'
            except (ValueError, OSError, EOFError, IndexError, struct.error) as error:
                info['errors'].append(str(error))
                info['scan_status'] = 'unsupported' if isinstance(error, UnsupportedNTFS) else 'failed'
            finally:
                if records is not None:
                    records.close()
        report['scan_status'] = 'finished'
    except (Cancelled, KeyboardInterrupt):
        report['scan_status'] = 'cancelled'
    except (ValueError, OSError, EOFError, IndexError, struct.error) as error:
        report['scan_status'] = 'failed'
        report['errors'].append(str(error))
    finally:
        if disk:
            disk.close()
        after = source.stat()
        report['source_unchanged_stat'] = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
        if not report['source_unchanged_stat']:
            report['errors'].append('Source changed during recovery; all outputs require review')
        with (output / 'recovery_manifest.json').open('x', encoding='utf-8') as fh:
            json.dump(report, fh, ensure_ascii=True, indent=2)
            fh.flush(); os.fsync(fh.fileno())
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, help='Immutable source VHDX, raw disk, or raw NTFS partition')
    parser.add_argument('output', type=Path, help='New output directory; never an existing directory')
    parser.add_argument('--source-format', choices=('auto', 'vhdx', 'raw'), default='auto')
    parser.add_argument('--partition-offset', type=int, help='Explicit logical partition start in bytes')
    parser.add_argument('--partition-size', type=int, help='Explicit logical partition length in bytes')
    parser.add_argument('--raw-sector-size', type=int, choices=(512, 4096), default=512, help='Raw disk partition-table sector size; NTFS itself currently requires 512')
    parser.add_argument('--damaged-range', action='append', default=[], metavar='START:END', help='Known damaged/encrypted physical byte interval, end exclusive; repeatable')
    parser.add_argument('--max-records', type=int, default=100000)
    parser.add_argument('--max-file-bytes', type=int, default=1024**4)
    parser.add_argument('--max-total-bytes', type=int, default=1024**4)
    parser.add_argument('--chunk-size', type=int, default=1024**2)
    parser.add_argument('--allow-partial-bat', action='store_true', help='VHDX only: explicitly retain independently valid BAT mappings while rejecting damaged mappings; critical metadata validation remains strict')
    parser.add_argument('--metadata-only', action='store_true', help='Index metadata/runlists without reading or exporting file payloads; not a resumable scan')
    parser.add_argument('--include-system', action='store_true', help='Also export NTFS system-file DATA streams')
    args = vars(parser.parse_args())
    try:
        args['damaged_ranges'] = [tuple(int(v, 0) for v in item.split(':')) for item in args.pop('damaged_range')]
        if any(len(pair) != 2 for pair in args['damaged_ranges']):
            raise ValueError('Expected START:END')
        report = recover(**args)
    except (ValueError, OSError) as error:
        parser.exit(2, f'{error}\n')
    print(json.dumps(report, indent=2))
    return 1 if report['scan_status'] == 'failed' else 0


if __name__ == '__main__':
    raise SystemExit(main())
