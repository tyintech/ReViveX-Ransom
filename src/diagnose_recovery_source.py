"""Read-only, metadata-only triage for large recovery sources.

No mounting, payload scan, decryption or full-image hashing. Reports intentionally
omit source paths, disk identifiers and ransomware public-key material.
"""
import argparse
import json
import os
from pathlib import Path

from analyze_gentlemen_pairs import footer, geometry
from revivex_vhdx import VHDXReader


def diagnose(source):
    source = Path(source)
    if not source.is_file():
        raise ValueError('Source must be a regular file')
    initial = source.stat()
    report = {
        'schema': 'revivex.source-diagnostic', 'schema_version': 1,
        'physical_size': initial.st_size, 'source_access': 'read_only',
        'full_image_hash_performed': False, 'guest_payload_scanned': False,
        'original_content_completeness': 'unknown', 'signatures': {},
        'limitations': [
            'Metadata validation does not prove that guest file data is unencrypted or intact.',
            'Inferred ransomware ranges are hypotheses, not a decryption key or confirmed damage map.',
            'Unavailable VHDX mapping prevents reliable logical file recovery; raw salvage remains a separate method.',
            'Active logs and differencing chains require separate validated handling; this diagnostic never changes them.',
        ],
    }
    with source.open('rb') as stream:
        for name, offset, expected in (
            ('file_identifier', 0, b'vhdxfile'), ('header_1', 65536, b'head'),
            ('header_2', 131072, b'head'), ('region_table_1', 196608, b'regi'),
            ('region_table_2', 262144, b'regi'),
        ):
            stream.seek(offset)
            report['signatures'][name] = {'offset': offset, 'present': stream.read(len(expected)) == expected}
    inferred = []
    try:
        marker = footer(source)
    except ValueError:
        report['ransomware_marker'] = 'not_recognized'
    else:
        report['ransomware_marker'] = {
            'family_marker': 'GENTLEMEN', 'mode': marker['mode'],
            'footer_size': marker['footer_size'], 'body_size': marker['body_size'],
            'identity_not_proven_by_marker': True,
        }
        try:
            inferred = geometry(marker['body_size'], marker['mode'])
        except ValueError:
            pass
        report['inferred_damage_ranges'] = [list(pair) for pair in inferred]
        report['inferred_ranges_overlap_header_copies'] = all(
            any(start < offset + 4096 and offset < end for start, end in inferred)
            for offset in (65536, 131072)
        )
    try:
        with VHDXReader(source) as disk:
            evidence = disk.evidence
            report['logical_mapping'] = 'validated_metadata_only'
            report['vhdx'] = {key: evidence[key] for key in (
                'header_offset', 'header_sequence', 'region_table_offset',
                'virtual_size', 'block_size', 'sector_size', 'disk_type',
                'payload_blocks', 'unknown_payload_blocks',
            ) if key in evidence}
            report['metadata_warnings'] = evidence.get('warnings', [])
    except (OSError, ValueError) as error:
        report['logical_mapping'] = 'unavailable'
        # Errors may include source paths: redact known spellings before sharing.
        detail = str(error).replace(str(source.resolve()), '[source]').replace(str(source), '[source]')
        report['mapping_error'] = {'type': type(error).__name__, 'detail': detail[:600]}
    final = source.stat()
    report['source_stat_unchanged'] = (
        initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns
    ) == (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
    if not report['source_stat_unchanged']:
        report['logical_mapping'] = 'invalidated_source_changed'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--report', type=Path, help='New JSON file; never overwrite existing files')
    args = parser.parse_args(argv)
    result = diagnose(args.source)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.report:
        with args.report.open('x', encoding='utf-8') as output:
            output.write(text + '\n')
            output.flush()
            os.fsync(output.fileno())
    print(text)
    return 0 if result['logical_mapping'] == 'validated_metadata_only' else 2


if __name__ == '__main__':
    raise SystemExit(main())
