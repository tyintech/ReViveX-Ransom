"""Conservative, read-only fixed/dynamic VHDX logical address translation.

Format reference: Microsoft [MS-VHDX], sections 2.2, 2.5 and 2.6:
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-vhdx/83e061f8-f6e2-4de1-91bd-5d518a43d477
Only FULLY_PRESENT and explicitly ZERO blocks yield bytes. NOT_PRESENT,
UNDEFINED and UNMAPPED are not proof of original zero content and raise.
Dissect's VHDX API was evaluated (https://github.com/fox-it/dissect.hypervisor):
its permissive zero-fill and checksum handling do not meet this recovery policy.
No guest code, mounting, source modification, log replay or decryption occurs.
Checksums protect headers/tables, NOT metadata items or payload authenticity.
"""
from __future__ import annotations

import io
import hashlib
import os
import struct
from pathlib import Path
from uuid import UUID

from revivex_source_io import open_source_readonly

MB = 1024 * 1024
MAX_READ_SIZE = 64 * MB
BAT_GUID = UUID('2dc27766-f623-4200-9d64-115e9bfd4a08')
METADATA_GUID = UUID('8b7ca206-4790-4b9a-b8fe-575f050f886e')
FILE_PARAMETERS_GUID = UUID('caa16737-fa36-4d43-b3b6-33f0aa44e76b')
DISK_SIZE_GUID = UUID('2fa54224-cd1b-4876-b211-5dbed83bf4b8')
DISK_ID_GUID = UUID('beca12ab-b2e6-4523-93ef-c309e000c746')
LOGICAL_SECTOR_GUID = UUID('8141bf1d-a96f-4709-ba47-f233a8faab5f')
PHYSICAL_SECTOR_GUID = UUID('cda348c7-445d-4471-9cc9-e9885251c556')
PARENT_GUID = UUID('a8d35f2d-b30b-454d-abf7-d3d84834ab0c')


class VHDXError(OSError):
    """Invalid or unreadable container; no recovery success is implied."""


class UnsupportedVHDXError(VHDXError):
    """A required feature cannot be interpreted safely."""


class UnreadableRangeError(VHDXError):
    def __init__(self, logical_offset, length, reason, physical_offset=None):
        self.logical_offset = logical_offset
        self.length = length
        self.reason = reason
        self.physical_offset = physical_offset
        super().__init__(f'Unreadable logical range [{logical_offset}, {logical_offset + length}): {reason}')


def _crc_table():
    result = []
    for value in range(256):
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        result.append(value)
    return tuple(result)


_CRC_TABLE = _crc_table()


def crc32c(data):
    """Castagnoli CRC with standard initial/final complements."""
    crc = 0xffffffff
    for value in data:
        crc = _CRC_TABLE[(crc ^ value) & 255] ^ (crc >> 8)
    return crc ^ 0xffffffff


def _checksum_valid(data, signature):
    return (data[:len(signature)] == signature and
            struct.unpack_from('<I', data, 4)[0] == crc32c(data[:4] + b'\0' * 4 + data[8:]))


def _overlaps(a, b):
    return a[0] < b[1] and b[0] < a[1]


def _disjoint(spans):
    ordered = sorted(spans)
    for a, b in zip(ordered, ordered[1:]):
        if a[1] > b[0]:
            raise VHDXError('Overlapping container structures')


class VHDXReader(io.RawIOBase):
    """Open a source path using rb. Damage intervals are half-open physical bytes.

    Reads are exact except at logical EOF. An unknown byte causes the entire
    read to fail, with no partial data returned and no cursor advance. This
    reader is not thread-safe. Source files must remain stable while open.
    allow_partial_bat is explicit salvage of readable malformed BAT entries;
    every conflicting allocation becomes unreadable. Critical metadata and
    physical BAT read failures remain fatal. This does not authenticate healthy
    payloads or prove original-file integrity. Maximum 10000 faulty entries.
    """
    def __init__(self, path, *, damaged_ranges=(), allow_partial_bat=False):
        super().__init__()
        self.path = Path(path)
        self._position = 0
        self.allow_partial_bat = bool(allow_partial_bat)
        self._bat_faults = {}
        self._source = open_source_readonly(self.path)
        self.evidence = {'source_access': 'read_only', 'format': 'VHDX',
                         'unknown_blocks': 'raise_without_zero_fill',
                         'payload_integrity': 'not_authenticated', 'warnings': [],
                         'allow_partial_bat': self.allow_partial_bat,
                         'logical_mapping_complete': True, 'partial_bat_errors': []}
        try:
            source_stat = os.fstat(self._source.fileno())
            self.physical_size = source_stat.st_size
            self._source_identity = (source_stat.st_size, source_stat.st_mtime_ns, source_stat.st_ctime_ns)
            self.evidence['source_stat'] = {'size': source_stat.st_size, 'mtime_ns': source_stat.st_mtime_ns, 'ctime_ns': source_stat.st_ctime_ns}
            self.damaged_ranges = sorted(tuple(x) for x in damaged_ranges)
            for start, end in self.damaged_ranges:
                if not isinstance(start, int) or not isinstance(end, int) or start < 0 or end <= start:
                    raise ValueError('Damage intervals must be nonnegative half-open byte ranges')
            self._load()
        except BaseException:
            self._source.close()
            super().close()
            raise

    def _physical(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.physical_size:
            raise VHDXError('Physical range outside source')
        if any(_overlaps((offset, offset + length), span) for span in self.damaged_ranges):
            raise VHDXError('Physical range intersects declared damage')
        self._source.seek(offset)
        parts, remaining = [], length
        while remaining:  # unbuffered raw reads may be short
            piece = self._source.read(remaining)
            if not piece:
                break
            parts.append(piece)
            remaining -= len(piece)
        value = b''.join(parts)
        if len(value) != length:
            raise VHDXError('Short physical read')
        return value

    def _copies(self, offsets, length, signature):
        copies = []
        for offset in offsets:
            try:
                data = self._physical(offset, length)
                if not _checksum_valid(data, signature):
                    raise VHDXError('Invalid signature or CRC-32C')
                copies.append((offset, data))
            except OSError as error:
                self.evidence['warnings'].append(f'Invalid {signature.decode()} copy at {offset}: {error}')
        if not copies:
            raise VHDXError(f'No valid {signature.decode()} copy')
        return copies

    def _load(self):
        if self._physical(0, 8) != b'vhdxfile':
            raise VHDXError('Not a VHDX file; encrypted or damaged containers are unsupported')
        headers = self._copies((65536, 131072), 4096, b'head')
        if len(headers) == 2 and headers[0][1][8:16] == headers[1][1][8:16]:
            raise VHDXError('No uniquely current header: equal sequence numbers')
        header_offset, header = max(headers, key=lambda x: struct.unpack_from('<Q', x[1], 8)[0])
        if struct.unpack_from('<H', header, 66)[0] != 1:
            raise UnsupportedVHDXError('Unsupported VHDX version')
        if header[48:64] != bytes(16):
            raise UnsupportedVHDXError('Active log requires replay; source is left untouched')
        log_length, log_offset = struct.unpack_from('<IQ', header, 68)
        if log_length % MB or log_offset % MB or (log_length and (log_offset < MB or log_offset + log_length > self.physical_size)):
            raise VHDXError('Invalid log bounds')
        self.evidence.update(header_offset=header_offset, header_sequence=struct.unpack_from('<Q', header, 8)[0], active_log=False)
        tables = self._copies((196608, 262144), 65536, b'regi')
        parsed = [(offset, self._regions(data)) for offset, data in tables]
        if len(parsed) == 2 and parsed[0][1] != parsed[1][1]:
            raise VHDXError('Conflicting valid region table copies')
        table_offset, regions = parsed[0]
        self.evidence['region_table_offset'] = table_offset
        self.evidence['header_sha256'] = hashlib.sha256(header).hexdigest()
        self.evidence['region_table_sha256'] = hashlib.sha256(dict(tables)[table_offset]).hexdigest()
        reserved = [(0, MB)] + [(offset, offset + length) for offset, length, _ in regions.values()]
        if log_length:
            reserved.append((log_offset, log_offset + log_length))
        _disjoint(reserved)
        self._metadata(*regions[METADATA_GUID][:2])
        bat_offset, bat_length, _ = regions[BAT_GUID]
        count = (self.size + self.block_size - 1) // self.block_size
        ratio = (2**23 * self.sector_size) // self.block_size
        entries = count + (count - 1) // ratio
        if entries * 8 > bat_length:
            raise VHDXError('BAT too small for virtual disk')
        if entries > 8_000_000:
            raise UnsupportedVHDXError('BAT exceeds safe reader resource limit (8 million entries)')
        self._bat_offset = bat_offset
        self._chunk_ratio = ratio
        allocated = []
        bat_hash = hashlib.sha256()
        unknown = 0
        for index in range(entries):
            # Stream validation in 64 KiB windows; never load the whole BAT.
            if index % 8192 == 0:
                raw = self._physical(bat_offset + index * 8, min(8192, entries - index) * 8)
                bat_hash.update(raw)
            value = struct.unpack_from('<Q', raw, (index % 8192) * 8)[0]
            state, physical = value & 7, (value >> 20) * MB
            bitmap = (index + 1) % (ratio + 1) == 0
            if value & 0xffff8:
                self._bat_fault(index, 'Nonzero reserved BAT bits')
            if bitmap:
                if state != 0:
                    raise VHDXError('Allocated sector bitmap invalid for fixed/dynamic image')
            elif state not in (0, 1, 2, 3, 6):
                self._bat_fault(index, 'Reserved or partially-present payload BAT state', UnsupportedVHDXError)
            if physical:
                length = MB if bitmap else self.block_size
                if physical < MB or physical + length > self.physical_size:
                    self._bat_fault(index, 'BAT allocation outside source')
                if len(allocated) >= 1_000_000:
                    raise UnsupportedVHDXError('Allocated extent validation exceeds safe resource limit')
                # Even an invalid entry can conflict with a healthy mapping.
                allocated.append((physical, physical + length, index))
            elif state == 6:
                self._bat_fault(index, 'Present BAT entry has zero physical address')
            if not bitmap:
                unknown += state in (0, 1, 3)
        self._validate_allocations(reserved, allocated)
        self.evidence['partial_bat_errors'] = [
            {'bat_index': index, 'logical_offset': (index - index // (ratio + 1)) * self.block_size,
             'length': min(self.block_size, self.size - (index - index // (ratio + 1)) * self.block_size),
             'reason': reason}
            for index, reason in sorted(self._bat_faults.items())]
        self.evidence['logical_mapping_complete'] = not self._bat_faults and not unknown
        self.evidence['partial_bat'] = bool(self._bat_faults)
        self.evidence['used_bat_sha256'] = bat_hash.hexdigest()
        self.evidence.update(block_size=self.block_size, sector_size=self.sector_size,
                             virtual_size=self.size, payload_blocks=count, unknown_payload_blocks=unknown,
                             disk_type='fixed' if self.fixed else 'dynamic',
                             declared_damaged_ranges=[list(x) for x in self.damaged_ranges])

    def _bat_fault(self, index, reason, exception=VHDXError):
        # Sector bitmap corruption cannot be reconciled with supported disk types.
        if not self.allow_partial_bat or (index + 1) % (self._chunk_ratio + 1) == 0:
            raise exception(reason)
        if index not in self._bat_faults and len(self._bat_faults) >= 10_000:
            raise UnsupportedVHDXError('Partial BAT fault count exceeds safe limit (10000)')
        self._bat_faults.setdefault(index, reason)

    def _validate_allocations(self, reserved, allocated):
        if not self.allow_partial_bat:
            _disjoint(reserved + [(start, end) for start, end, _ in allocated])
            return
        # Sweep overlap-connected components. No allocation wins a conflict.
        spans = [(start, end, -1) for start, end in reserved] + allocated
        spans.sort()
        end = -1
        representative = -1
        for start, stop, index in spans:
            if start < end:
                for affected in (representative, index):
                    if affected >= 0:
                        self._bat_fault(affected, 'Ambiguous overlapping container allocation')
            else:
                representative = index
            end = max(end, stop)

    def _regions(self, data):
        count = struct.unpack_from('<I', data, 8)[0]
        if count > 2047:
            raise VHDXError('Invalid region entry count')
        regions = {}
        for i in range(count):
            guid_raw, offset, length, required = struct.unpack_from('<16sQII', data, 16 + i * 32)
            guid = UUID(bytes_le=guid_raw)
            if guid in regions or required not in (0, 1):
                raise VHDXError('Duplicate or invalid region')
            if guid not in (BAT_GUID, METADATA_GUID) and required:
                raise UnsupportedVHDXError(f'Unknown required region {guid}')
            if offset < MB or offset % MB or not length or length % MB or offset + length > self.physical_size:
                raise VHDXError('Invalid region bounds')
            regions[guid] = (offset, length, required)
        if not {BAT_GUID, METADATA_GUID} <= regions.keys():
            raise VHDXError('Missing BAT or metadata region')
        return regions

    def _metadata(self, offset, length):
        table = self._physical(offset, 65536)
        if table[:8] != b'metadata':
            raise VHDXError('Invalid metadata signature')
        metadata_hash = hashlib.sha256(table)
        count = struct.unpack_from('<H', table, 10)[0]
        if count > 2047 or table[8:10] != b'\0\0' or any(table[12:32]):
            raise VHDXError('Invalid metadata table')
        sizes = {FILE_PARAMETERS_GUID: 8, DISK_SIZE_GUID: 8, DISK_ID_GUID: 16,
                 LOGICAL_SECTOR_GUID: 4, PHYSICAL_SECTOR_GUID: 4}
        items, spans, seen = {}, [], set()
        users = 0
        for i in range(count):
            raw_guid, start, size, flags, reserved = struct.unpack_from('<16sIIII', table, 32 + 32 * i)
            guid = UUID(bytes_le=raw_guid)
            key = (guid, flags & 1)
            users += flags & 1
            if key in seen or flags & ~7 or reserved or users > 1024:
                raise VHDXError('Invalid or duplicate metadata entry')
            seen.add(key)
            if size > MB or (size and (start < 65536 or start + size > length)) or (not size and start):
                raise VHDXError('Invalid metadata item bounds')
            if size:
                spans.append((start, start + size))
            if guid == PARENT_GUID:
                raise UnsupportedVHDXError('Parent locator/differencing images are unsupported')
            if guid not in sizes or flags & 1:
                if flags & 4:
                    raise UnsupportedVHDXError(f'Unknown required metadata {guid}')
                continue
            expected_flags = 4 if guid == FILE_PARAMETERS_GUID else 6
            if flags != expected_flags or size != sizes[guid]:
                raise VHDXError('Invalid system metadata size or flags')
            items[guid] = self._physical(offset + start, size)
            metadata_hash.update(items[guid])
        _disjoint(spans)
        if items.keys() != sizes.keys():
            raise VHDXError('Required metadata missing')
        self.block_size, flags = struct.unpack('<II', items[FILE_PARAMETERS_GUID])
        if flags & 2:
            raise UnsupportedVHDXError('Differencing images require a verified parent chain')
        if flags & ~3 or self.block_size < MB or self.block_size > 256 * MB or self.block_size & (self.block_size - 1):
            raise VHDXError('Invalid file parameters')
        self.fixed = bool(flags & 1)
        self.size = struct.unpack('<Q', items[DISK_SIZE_GUID])[0]
        self.sector_size = struct.unpack('<I', items[LOGICAL_SECTOR_GUID])[0]
        self.physical_sector_size = struct.unpack('<I', items[PHYSICAL_SECTOR_GUID])[0]
        if self.sector_size not in (512, 4096) or self.physical_sector_size not in (512, 4096):
            raise VHDXError('Unsupported sector geometry')
        if not self.size or self.size > 64 * 1024**4 or self.size % self.sector_size:
            raise VHDXError('Invalid virtual disk size')
        self.evidence['system_metadata_sha256'] = metadata_hash.hexdigest()
        self.evidence['virtual_disk_id'] = str(UUID(bytes_le=items[DISK_ID_GUID]))

    def read_at(self, offset, length):
        self._checkClosed()
        current = os.fstat(self._source.fileno())
        if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != self._source_identity:
            raise VHDXError('Source changed while open; mapping no longer trusted')
        if offset < 0 or length < 0:
            raise ValueError('Negative read range')
        length = min(length, max(0, self.size - offset))
        if length > MAX_READ_SIZE:
            raise ValueError('Read exceeds 64 MiB safety limit; read in bounded chunks')
        result = []
        while length:
            block, within = divmod(offset, self.block_size)
            take = min(length, self.block_size - within)
            bat_index = block + block // self._chunk_ratio
            if bat_index in self._bat_faults:
                raise UnreadableRangeError(offset, take, self._bat_faults[bat_index])
            try:
                value = struct.unpack('<Q', self._physical(self._bat_offset + 8 * bat_index, 8))[0]
            except OSError as error:
                raise UnreadableRangeError(offset, take, f'Unreadable BAT entry: {error}') from error
            state, physical = value & 7, (value >> 20) * MB
            if state == 2:
                result.append(bytes(take))
            elif state == 6:
                try:
                    result.append(self._physical(physical + within, take))
                except OSError as error:
                    raise UnreadableRangeError(offset, take, str(error), physical + within) from error
            else:
                raise UnreadableRangeError(offset, take, f'BAT state {state} does not establish original bytes')
            offset += take
            length -= take
        return b''.join(result)

    def read(self, size=-1):
        data = self.read_at(self._position, max(0, self.size - self._position) if size is None or size < 0 else size)
        self._position += len(data)
        return data

    def readinto(self, buffer):
        data = self.read(len(buffer))
        buffer[:len(data)] = data
        return len(data)

    def seek(self, offset, whence=0):
        self._checkClosed()
        if whence not in (0, 1, 2):
            raise ValueError('Invalid whence')
        position = offset + (0 if whence == 0 else self._position if whence == 1 else self.size)
        if position < 0:
            raise ValueError('Negative seek')
        self._position = position
        return position

    def tell(self):
        self._checkClosed()
        return self._position

    def readable(self):
        return True

    def seekable(self):
        return True

    def writable(self):
        return False

    def write(self, data):
        raise io.UnsupportedOperation('VHDX source is read-only')

    def close(self):
        if hasattr(self, '_source'):
            self._source.close()
        super().close()


VhdxReader = VHDXReader
