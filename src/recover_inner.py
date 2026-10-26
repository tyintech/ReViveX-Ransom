#!/usr/bin/env python3
"""Experimental nested-ZIP salvage, not a general ZIP repair or decryptor.

Requires an explicitly named outer DEFLATE member without descriptors/ZIP64,
a damaged stream followed by an independently decodable stored-block suffix,
and an intact single-disk inner central directory. The suffix search tries at
most 256 stored blocks of at least 32768 bytes. Only complete CRC-verified
inner members are emitted. Missing ranges are never filled or invented.
"""
import argparse
import hashlib
import json
import struct
import zlib
from pathlib import Path

from salvage_zip import collision_key, getname, inflate, output_conflict, register_output

MAX_INPUT = 256 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024


def unpack(fmt, source, offset):
    if offset < 0 or offset + struct.calcsize(fmt) > len(source):
        raise ValueError('Truncated ZIP structure')
    return struct.unpack_from(fmt, source, offset)


def regions(data, member):
    offset = 0
    while True:
        offset = data.find(b'PK\x03\x04', offset)
        if offset < 0:
            raise ValueError('Named outer local header missing')
        try:
            h = unpack('<4s5H3I2H', data, offset)
            nl, xl = h[-2:]
            start = offset + 30 + nl + xl
            if start > len(data):
                raise ValueError('Truncated outer local header')
            raw = data[offset + 30:offset + 30 + nl]
            name = getname(raw, h[2], data[offset + 30 + nl:start])
        except (ValueError, UnicodeError):
            offset += 4
            continue
        if name == member:
            break
        offset += 4
    if h[3] != 8 or h[2] & 0x2049 or h[7] == 0xffffffff or h[8] == 0xffffffff:
        raise ValueError('Outer encryption, descriptors, ZIP64, or non-DEFLATE methods unsupported')
    end = start + h[7]
    if end > len(data) or h[8] > MAX_FILE:
        raise ValueError('Outer member exceeds input or expanded-size limit')
    decoder = zlib.decompressobj(-15)
    prefix = bytearray()
    failed = None
    failed_byte = None
    for cursor in range(start, end, 4096):
        checkpoint = decoder.copy()
        try:
            prefix.extend(decoder.decompress(data[cursor:min(cursor + 4096, end)], MAX_FILE - len(prefix) + 1))
            if len(prefix) > MAX_FILE or decoder.unconsumed_tail:
                raise ValueError('Prefix output limit exceeded')
        except zlib.error:
            # zlib discards all output from a failing call. Replay only that
            # bounded chunk from its checkpoint, retaining bytes before failure.
            decoder = checkpoint
            failed = cursor
            for exact in range(cursor, min(cursor + 4096, end)):
                try:
                    part = decoder.decompress(data[exact:exact + 1], MAX_FILE - len(prefix) + 1)
                except zlib.error:
                    failed_byte = exact
                    break
                prefix.extend(part)
                if len(prefix) > MAX_FILE or decoder.unconsumed_tail:
                    raise ValueError('Prefix output limit exceeded')
            break
    if failed is None:
        raise ValueError('No damaged stream detected; use ordinary ZIP salvage instead')
    attempts = 0
    for cursor in range(failed, end - 4):
        size, complement = struct.unpack_from('<HH', data, cursor)
        if size < 32768 or size ^ complement != 65535 or cursor + 4 + size > end:
            continue
        attempts += 1
        if attempts > 256:
            raise ValueError('Suffix candidate limit reached')
        for final_block in (False, True):
            try:
                decoder = zlib.decompressobj(-15)
                suffix = decoder.decompress(bytes([int(final_block)]) + data[cursor:end], h[8] + 1)
                if len(suffix) > h[8] or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                    continue
            except zlib.error:
                continue
            return bytes(prefix), suffix, dict(outer_header=offset, outer_data_start=start,
                outer_data_end=end, first_failed_chunk=failed, first_failed_byte=failed_byte,
                candidate_attempts=attempts, restart_final_block=final_block,
                restart_len_field=cursor, prefix_size=len(prefix), suffix_size=len(suffix))
    raise ValueError('No independently decodable suffix')


def extract(prefix, suffix, output, report):
    end = len(suffix)
    minimum = max(0, len(suffix) - 22 - 65535)
    while True:
        end = suffix.rfind(b'PK\x05\x06', minimum, end)
        if end < 0:
            raise ValueError('No consistent inner end record within comment limit')
        try:
            _, disk, cd_disk, on_disk, count, cd_size, cd_offset, comment = unpack('<4s4H2IH', suffix, end)
        except ValueError:
            continue
        if (disk or cd_disk or on_disk != count or count == 65535
                or end + 22 + comment != len(suffix) or cd_size > end
                or cd_offset < end - cd_size):
            continue
        # A comment may contain a full EOCD-looking structure, not just magic.
        # Require the referenced central-directory layout before selecting it.
        cursor = end - cd_size
        valid = True
        for _ in range(count):
            if cursor + 46 > end or suffix[cursor:cursor + 4] != b'PK\x01\x02':
                valid = False
                break
            name_length, extra_length, comment_length = struct.unpack_from('<HHH', suffix, cursor + 28)
            cursor += 46 + name_length + extra_length + comment_length
        if valid and cursor == end:
            break
    position = end - cd_size
    base = cd_offset - position
    if position < 0 or base < 0:
        raise ValueError('Central directory outside decoded suffix')
    report.update(central_entries=count, suffix_original_offset=base)
    used = set()
    file_keys = set()
    for _ in range(count):
        c = unpack('<4s6H3I5H2I', suffix, position)
        if c[0] != b'PK\x01\x02':
            raise ValueError('Invalid central directory signature')
        _, made, version, flags, method, tm, dt, crc, cs, us, nl, xl, cl, disk, ia, ea, local_offset = c
        next_position = position + 46 + nl + xl + cl
        if next_position > end:
            raise ValueError('Truncated central member')
        raw = suffix[position + 46:position + 46 + nl]
        extra = suffix[position + 46 + nl:position + 46 + nl + xl]
        position = next_position
        record = dict(status='failed', size=us, crc32=f'{crc:08x}', local_header_offset=local_offset)
        report['records'].append(record)
        try:
            name = getname(raw, flags, extra)
            record['name'] = name
            if flags & 0x2041 or method not in (0, 8) or disk or version > 63 or 0xffffffff in (cs, us, local_offset) or (ea >> 16) & 0o170000 == 0o120000:
                record.update(status='unsupported', error='Unsupported encrypted, split, ZIP64, symlink, or compression member')
                continue
            local = local_offset - base
            source, region = (suffix, 'suffix') if local >= 0 else (prefix, 'prefix')
            if local < 0:
                local = local_offset
            record.update(region=region, region_offset=local)
            h = unpack('<4s5H3I2H', source, local)
            ds = local + 30 + h[-2] + h[-1]
            if h[0] != b'PK\x03\x04' or h[2] != flags or h[3] != method or source[local + 30:local + 30 + h[-2]] != raw:
                raise ValueError('Local member missing or inconsistent in surviving bytes')
            if ds + cs > len(source):
                raise ValueError('Compressed member crosses damaged gap')
            if not flags & 8 and (h[6], h[7], h[8]) != (crc, cs, us):
                raise ValueError('Local and central CRC or sizes disagree')
            if us > MAX_FILE or report['recovered_bytes'] + us > MAX_TOTAL:
                record.update(status='limit_exceeded', error='Output size limit exceeded')
                continue
            if method == 8:
                content, _ = inflate(source, ds, cs, us)
            else:
                if cs != us:
                    raise ValueError('Stored member sizes disagree')
                content = source[ds:ds + cs]
            if len(content) != us or zlib.crc32(content) != crc:
                raise ValueError('Uncompressed size or CRC mismatch')
            root = output / 'files'
            target = root.joinpath(*name.rstrip('/').split('/'))
            key = collision_key(target)
            if output_conflict(target, used, file_keys):
                target = output / 'duplicates' / str(local_offset) / Path(*name.rstrip('/').split('/'))
                record['preserved_duplicate'] = True
            if any(p.is_symlink() for p in (target, *target.parents)):
                raise ValueError('Symlink output rejected')
            if name.endswith('/'):
                if content:
                    raise ValueError('Nonempty directory')
                target.mkdir(parents=True, exist_ok=True)
                record.update(status='directory', entry_kind='directory', output=target.relative_to(output).as_posix())
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open('xb') as stream:
                    stream.write(content)
                record.update(status='recovered', entry_kind='file', output=target.relative_to(output).as_posix(), sha256=hashlib.sha256(content).hexdigest(),
                              provenance='source_bytes_only_not_original_verified', validation='size_crc32_complete_stream')
                report['recovered_bytes'] += len(content)
            register_output(target, output, name.endswith('/'), used, file_keys)
        except (ValueError, UnicodeError, zlib.error, OSError) as error:
            record['error'] = str(error)
    if position != end:
        raise ValueError('Central directory size or entry count mismatch')


def recover(source, output, member):
    source, output = Path(source), Path(output)
    if output.exists() or any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('Output must be new, with no symlink ancestors')
    original = source.stat()
    if original.st_size > MAX_INPUT:
        raise ValueError('Input exceeds 256 MiB limit')
    output.mkdir(parents=True)
    report = dict(schema='revivex.experimental-nested-zip', schema_version=1, status='failed', input=str(source), outer_member=member, records=[], recovered_bytes=0,
                  warning=__doc__)
    try:
        data = source.read_bytes()
        report['input_sha256'] = hashlib.sha256(data).hexdigest()
        prefix, suffix, details = regions(data, member)
        report.update(details)
        extract(prefix, suffix, output, report)
        final = source.stat()
        report['source_size_and_mtime_unchanged'] = (original.st_size, original.st_mtime_ns) == (final.st_size, final.st_mtime_ns)
        report['status'] = 'partial_salvage' if report['source_size_and_mtime_unchanged'] else 'source_changed'
    except (ValueError, OSError, zlib.error) as error:
        report['error'] = str(error)
    finally:
        report['recovered_files'] = sum(r['status'] == 'recovered' for r in report['records'])
        report['unprocessed_entries'] = max(0, report.get('central_entries', 0) - len(report['records']))
        with (output / 'manifest.json').open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=True, indent=2)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--outer-member', required=True, help='Exact archive member name, including its directory')
    args = parser.parse_args()
    report = recover(args.input, args.output, args.outer_member)
    print(json.dumps({k: v for k, v in report.items() if k != 'records'}, indent=2))
    return 1 if report['status'] in ('failed', 'source_changed') else 0


if __name__ == '__main__':
    raise SystemExit(main())
