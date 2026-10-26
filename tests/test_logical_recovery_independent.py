"""Independent synthetic VHDX/NTFS adversarial fixtures, no incident payloads.

Layout constants derived from Microsoft MS-VHDX sections 2.2, 2.5, 2.6.
CRC implementation and container fixture do not use production builder code.
"""
from sparse_fixtures import sparse_truncate
import hashlib
import json
import struct
import tempfile
import tracemalloc
import sqlite3
import subprocess
import sys
import threading
import os
import unittest
from pathlib import Path
from uuid import UUID
from unittest.mock import patch

from revivex_vhdx import VHDXReader, VHDXError, UnreadableRangeError

MIB = 1048576


def fixture_crc(data):
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return crc ^ 0xffffffff


def checksum(block):
    struct.pack_into('<I', block, 4, 0)
    struct.pack_into('<I', block, 4, fixture_crc(block))
    return block


def make_container(path, *, blocks=2, sector=512, states=None, bitmap_state=0, equal_headers=False, active_log=False):
    """Small physical file even when logical BAT spans the 4 GiB boundary."""
    image = bytearray(7 * MIB)
    image[:8] = b'vhdxfile'
    for number, offset in enumerate((65536, 131072), 1):
        header = bytearray(4096)
        header[:4] = b'head'
        struct.pack_into('<Q', header, 8, 1 if equal_headers else number)
        header[16:32] = UUID(int=1).bytes_le
        header[32:48] = UUID(int=2).bytes_le
        if active_log:
            header[48:64] = UUID(int=3).bytes_le
        struct.pack_into('<HHIQ', header, 64, 0, 1, MIB, 3 * MIB)
        image[offset:offset + 4096] = checksum(header)
    regions = bytearray(65536)
    regions[:4] = b'regi'
    struct.pack_into('<I', regions, 8, 2)
    for index, (guid, offset) in enumerate((
        ('8b7ca206-4790-4b9a-b8fe-575f050f886e', MIB),
        ('2dc27766-f623-4200-9d64-115e9bfd4a08', 2*MIB))):
        struct.pack_into('<16sQII', regions, 16 + index*32, UUID(guid).bytes_le, offset, MIB, 1)
    checksum(regions)
    image[196608:262144] = regions
    image[262144:327680] = regions
    metadata = bytearray(MIB)
    metadata[:8] = b'metadata'
    items = [
        ('caa16737-fa36-4d43-b3b6-33f0aa44e76b', struct.pack('<II', MIB, 0), 4),
        ('2fa54224-cd1b-4876-b211-5dbed83bf4b8', struct.pack('<Q', blocks*MIB), 6),
        ('beca12ab-b2e6-4523-93ef-c309e000c746', UUID(int=7).bytes_le, 6),
        ('8141bf1d-a96f-4709-ba47-f233a8faab5f', struct.pack('<I', sector), 6),
        ('cda348c7-445d-4471-9cc9-e9885251c556', struct.pack('<I', 4096), 6)]
    struct.pack_into('<H', metadata, 10, len(items))
    cursor = 65536
    for index, (guid, data, flags) in enumerate(items):
        struct.pack_into('<16sIIII', metadata, 32+index*32, UUID(guid).bytes_le, cursor, len(data), flags, 0)
        metadata[cursor:cursor+len(data)] = data
        cursor += len(data)
    image[MIB:2*MIB] = metadata
    ratio = (1 << 23) * sector // MIB
    for block in range(blocks):
        table_index = block + block // ratio
        state, address = (states or {}).get(block, (2, 0))
        struct.pack_into('<Q', image, 2*MIB + 8*table_index, address | state)
    if blocks > ratio:
        struct.pack_into('<Q', image, 2*MIB + ratio*8, (6*MIB if bitmap_state else 0) | bitmap_state)
    image[4*MIB:5*MIB] = b'A' * MIB
    image[5*MIB:6*MIB] = b'B' * MIB
    path.write_bytes(image)
    return image


class IndependentVhdxTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / 'synthetic.vhdx'

    def test_partial_bat_preserves_only_independent_healthy_blocks(self):
        make_container(self.path, blocks=3, states={0:(6,4*MIB),1:(6,8*MIB),2:(6,5*MIB)})
        with self.assertRaises(VHDXError):
            VHDXReader(self.path)
        with VHDXReader(self.path,allow_partial_bat=True) as disk:
            self.assertEqual(disk.read_at(0,3),b'AAA')
            self.assertEqual(disk.read_at(2*MIB,3),b'BBB')
            self.assertTrue(disk.evidence['partial_bat'])
            self.assertFalse(disk.evidence['logical_mapping_complete'])
            disk.seek(MIB-1)
            with self.assertRaises(UnreadableRangeError):
                disk.read(2)
            self.assertEqual(disk.tell(),MIB-1)

    def test_partial_bat_overlap_chain_invalidates_every_participant(self):
        image = make_container(self.path,blocks=3,states={0:(6,4*MIB),1:(6,5*MIB),2:(6,6*MIB)})
        struct.pack_into('<I',image,MIB+65536,2*MIB)
        struct.pack_into('<Q',image,MIB+65544,6*MIB)
        self.path.write_bytes(image)
        with VHDXReader(self.path,allow_partial_bat=True) as disk:
            self.assertEqual(len(disk.evidence['partial_bat_errors']),3)
            for offset in (0,2*MIB,4*MIB):
                with self.assertRaises(UnreadableRangeError):
                    disk.read_at(offset,1)

    def test_partial_bat_reserved_bits_cannot_hide_allocation_conflict(self):
        image = make_container(self.path,blocks=3,states={0:(6,4*MIB),1:(6,4*MIB),2:(6,5*MIB)})
        struct.pack_into('<Q',image,2*MIB,(4*MIB)|6|8)
        self.path.write_bytes(image)
        with VHDXReader(self.path,allow_partial_bat=True) as disk:
            for offset in (0,MIB):
                with self.assertRaises(UnreadableRangeError):
                    disk.read_at(offset,1)
            self.assertEqual(disk.read_at(2*MIB,3),b'BBB')

    def test_partial_bat_never_relaxes_critical_metadata(self):
        for kwargs,damage in (({'active_log':True},()),({'blocks':4097,'bitmap_state':6},()),({},((2*MIB,2*MIB+8),))):
            with self.subTest(kwargs=kwargs,damage=damage):
                make_container(self.path,**kwargs)
                with self.assertRaises(VHDXError):
                    VHDXReader(self.path,allow_partial_bat=True,damaged_ranges=damage)

    def test_independent_crc_vector_and_noncontiguous_mapping(self):
        self.assertEqual(fixture_crc(b'123456789'), 0xe3069283)
        before = make_container(self.path, states={0:(6,5*MIB),1:(6,4*MIB)})
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.read_at(MIB-3,6), b'BBBAAA')
            self.assertFalse(disk.writable())
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), hashlib.sha256(before).digest())

    def test_bat_chunk_bitmap_gap_is_not_payload(self):
        make_container(self.path, blocks=4097, states={4095:(6,4*MIB),4096:(6,5*MIB)})
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.read_at(4096*MIB-2,4), b'AABB')

    def test_present_bitmap_invalid_for_supported_dynamic_image(self):
        make_container(self.path, blocks=4097, bitmap_state=6)
        with self.assertRaises(VHDXError):
            VHDXReader(self.path)

    def test_unknown_states_raise_instead_of_zero_filling(self):
        for state in (0,1,3):
            with self.subTest(state=state):
                make_container(self.path, states={0:(6,4*MIB),1:(state,0)})
                with VHDXReader(self.path) as disk:
                    disk.seek(MIB-1)
                    with self.assertRaises(UnreadableRangeError):
                        disk.read(2)
                    self.assertEqual(disk.tell(), MIB-1)

    def test_declared_payload_damage_never_returns_partial_or_zero(self):
        make_container(self.path, states={0:(6,4*MIB),1:(6,5*MIB)})
        with VHDXReader(self.path, damaged_ranges=[(4*MIB+100,4*MIB+101)]) as disk:
            self.assertEqual(disk.read_at(0,100), b'A'*100)
            with self.assertRaises(UnreadableRangeError):
                disk.read_at(99,3)
            self.assertEqual(disk.read_at(MIB,3), b'BBB')

    def test_corrupt_primary_header_uses_valid_secondary(self):
        image = make_container(self.path)
        image[65536+4] ^= 1
        self.path.write_bytes(image)
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.evidence['header_offset'],131072)
            self.assertTrue(disk.evidence['warnings'])

    def test_equal_headers_active_log_and_payload_overlap_rejected(self):
        for kwargs in ({'equal_headers':True},{'active_log':True},{'states':{0:(6,MIB)}}):
            with self.subTest(kwargs=kwargs):
                make_container(self.path, **kwargs)
                with self.assertRaises(VHDXError):
                    VHDXReader(self.path)

    def test_metadata_overlap_rejected_without_payload_reads(self):
        image = make_container(self.path)
        # Disk size points at file parameters, an overlapping metadata extent.
        struct.pack_into('<I', image, MIB+32+32+16,65536)
        self.path.write_bytes(image)
        with self.assertRaises(VHDXError):
            VHDXReader(self.path)

    def test_logical_read_all_is_bounded_before_allocation(self):
        make_container(self.path, blocks=65)
        with VHDXReader(self.path) as disk:
            with self.assertRaises(ValueError):
                disk.read()
            self.assertEqual(disk.tell(),0)

    def test_diagnostic_reads_metadata_not_guest_payload(self):
        from diagnose_recovery_source import diagnose
        make_container(self.path,states={0:(6,4*MIB),1:(6,5*MIB)})
        original = VHDXReader._physical
        reads = []
        def physical(reader,offset,length):
            reads.append((offset,length))
            return original(reader,offset,length)
        with patch.object(VHDXReader,'_physical',physical):
            result = diagnose(self.path)
        self.assertEqual(result['logical_mapping'],'validated_metadata_only')
        self.assertTrue(all(offset+length <= 4*MIB for offset,length in reads))
        self.assertLess(sum(length for _,length in reads),256*1024)
        encoded = json.dumps(result)
        self.assertNotIn(str(self.path),encoded)
        self.assertNotIn('virtual_disk_id',encoded)
        self.assertNotIn('ephemeral_public_key',encoded)

    def test_diagnostic_secondary_header_fallback_and_both_corrupt(self):
        from diagnose_recovery_source import diagnose
        image = make_container(self.path)
        image[65536+4] ^= 1
        self.path.write_bytes(image)
        result = diagnose(self.path)
        self.assertEqual(result['logical_mapping'],'validated_metadata_only')
        self.assertEqual(result['vhdx']['header_offset'],131072)
        image[131072+4] ^= 1
        self.path.write_bytes(image)
        result = diagnose(self.path)
        self.assertEqual(result['logical_mapping'],'unavailable')
        self.assertEqual(result['original_content_completeness'],'unknown')

    def test_four_kib_sector_geometry(self):
        make_container(self.path, sector=4096, states={0:(6,4*MIB)})
        with VHDXReader(self.path) as disk:
            self.assertEqual(disk.sector_size,4096)
            self.assertEqual(disk.read_at(4093,6),b'A'*6)


def independent_resident(kind, value, attribute_id=0):
    raw = bytearray((24 + len(value) + 7)//8*8)
    struct.pack_into('<II', raw, 0, kind, len(raw))
    struct.pack_into('<H', raw, 14, attribute_id)
    struct.pack_into('<IH', raw, 16, len(value), 24)
    raw[24:24+len(value)] = value
    return raw


def independent_name(name, parent=5, parent_sequence=1):
    encoded = name.encode('utf-16le')
    value = bytearray(66+len(encoded))
    struct.pack_into('<Q', value, 0, parent | parent_sequence << 48)
    value[64:66] = bytes((len(encoded)//2,1))
    value[66:] = encoded
    return independent_resident(0x30,value)


def independent_nonresident(run_pairs, size, initialized=None, flags=0):
    """Each pair is (positive cluster count, signed delta or None for sparse)."""
    encoded = bytearray()
    clusters = 0
    for count, delta in run_pairs:
        clusters += count
        count_width = max(1,(count.bit_length()+8)//8)
        delta_width = 0 if delta is None else next(width for width in range(1,9) if -(1<<(width*8-1)) <= delta < (1<<(width*8-1)))
        encoded.append(count_width | delta_width<<4)
        encoded.extend(count.to_bytes(count_width,'little'))
        if delta is not None:
            encoded.extend(int(delta).to_bytes(delta_width,'little',signed=True))
    encoded.append(0)
    header_size = 72 if flags & 0x8000 else 64
    raw = bytearray((header_size+len(encoded)+7)//8*8)
    struct.pack_into('<II', raw,0,0x80,len(raw))
    raw[8] = 1
    struct.pack_into('<H',raw,12,flags)
    struct.pack_into('<QQH',raw,16,0,clusters-1 if clusters else (1<<64)-1,header_size)
    struct.pack_into('<QQQ',raw,40,clusters*4096,size,size if initialized is None else initialized)
    if flags & 0x8000:
        struct.pack_into('<Q',raw,64,sum(count for count,delta in run_pairs if delta is not None)*4096)
    raw[header_size:header_size+len(encoded)] = encoded
    return raw


def independent_record(number, name, attrs=(), parent=5, directory=False):
    raw = bytearray(1024)
    raw[:4] = b'FILE'
    struct.pack_into('<HH',raw,4,48,3)
    struct.pack_into('<HH',raw,16,1,1)
    all_attrs = independent_name(name,parent) + b''.join(attrs) + b'\xff'*4
    struct.pack_into('<HHII',raw,20,56,3 if directory else 1,56+len(all_attrs),1024)
    struct.pack_into('<I',raw,44,number)
    raw[56:56+len(all_attrs)] = all_attrs
    raw[48:50] = b'\xab\xcd'
    raw[50:52],raw[52:54] = raw[510:512],raw[1022:1024]
    raw[510:512] = raw[1022:1024] = raw[48:50]
    return bytes(raw)


def independent_ntfs(path, *, file_name='first.bin', sparse=False, initialized=None):
    image = bytearray(128*4096)
    image[:3] = b'\xeb\x52\x90'
    image[3:11] = b'NTFS    '
    struct.pack_into('<HB',image,11,512,8)
    image[21] = 0xf8
    struct.pack_into('<QQQ',image,40,len(image)//512,4,16)
    struct.pack_into('<b',image,64,-10)
    struct.pack_into('<Q',image,72,0x123456789)
    image[510:512] = b'\x55\xaa'
    image[-512:] = image[:512]
    mft = independent_record(0,'$MFT',[independent_nonresident([(8,4)],32768)])
    records = {0:mft,5:independent_record(5,'.',directory=True),
        16:independent_record(16,'folder',directory=True),
        17:independent_record(17,file_name,[independent_nonresident([(1,40),(1,None if sparse else 2)],8192,initialized,0x8000 if sparse else 0)],parent=16),
        18:independent_record(18,'second.bin',[independent_resident(0x80,b'hello')],parent=16),
        19:independent_record(19,'empty',parent=16,directory=True)}
    for number, record in records.items():
        image[4*4096+number*1024:4*4096+(number+1)*1024] = record
    image[16*4096:16*4096+1024] = mft
    image[40*4096:41*4096] = b'A'*4096
    image[42*4096:43*4096] = b'B'*4096
    path.write_bytes(image)
    return image


class IndependentLogicalNtfsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root/'ntfs.raw'

    def recover(self, **kwargs):
        from recover_vhdx_files import recover
        return recover(self.source,self.root/'out',**kwargs)

    def file_row(self, report, number):
        return next(row for row in report['files'] if row.get('record_number') == number and row.get('stream_name') == '')

    def test_fragmented_file_and_parent_chain_from_independent_fixture(self):
        before = independent_ntfs(self.source)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',report)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096+b'B'*4096)
        self.assertIn('/folder/first.bin',row['paths'])
        self.assertEqual(report['completeness'],'unknown')
        self.assertEqual(self.source.read_bytes(),before)

    def test_damaged_second_run_preserves_prefix_without_zero_fill(self):
        independent_ntfs(self.source)
        report = self.recover(damaged_ranges=[(42*4096,43*4096)],chunk_size=4096)
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'partial',row)
        self.assertEqual(row['size'],4096)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096)
        self.assertEqual(self.file_row(report,18)['status'],'recovered')

    def test_declared_sparse_and_uninitialized_bytes_have_explicit_provenance(self):
        independent_ntfs(self.source,sparse=True,initialized=5000)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',row)
        self.assertTrue(row['sparse'])
        self.assertEqual(row['uninitialized_tail_zero_bytes'],3192)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096+b'\0'*4096)

    def test_damage_to_adjacent_mft_record_does_not_hide_healthy_file(self):
        independent_ntfs(self.source)
        bad = 4*4096 + 18*1024
        report = self.recover(damaged_ranges=[(bad,bad+1024)])
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',report)
        self.assertIn('/folder/first.bin',row['paths'])

    def test_long_original_name_is_preserved_without_export_failure(self):
        independent_ntfs(self.source,file_name='测'*100)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',row)
        self.assertIn('/folder/'+'测'*100,row['paths'])

    def test_backup_boot_accepts_ntfs3g_reserved_final_sector(self):
        image = independent_ntfs(self.source)
        struct.pack_into('<Q',image,40,len(image)//512-1)
        image[-512:] = image[:512]
        image[3:11] = b'BROKEN!!'
        self.source.write_bytes(image)
        report = self.recover(partition_offset=0,partition_size=len(image))
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',report)
        self.assertEqual(report['volumes'][0]['boot_source'],'validated_backup_at_partition_end')

    def test_empty_directory_and_nested_folder_provenance(self):
        independent_ntfs(self.source)
        report = self.recover()
        paths = [path for row in report.get('directories',[]) for path in row.get('paths',[])]
        self.assertIn('/folder/empty',paths)

    def test_stale_parent_sequence_never_fabricates_original_path(self):
        image = independent_ntfs(self.source)
        position = 4*4096 + 16*1024
        struct.pack_into('<H',image,position+16,2)
        self.source.write_bytes(image)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered')
        self.assertEqual(row['paths'],[])
        self.assertEqual(row['path_status'],'unknown')

    def test_same_basename_different_parents_remain_distinct(self):
        image = independent_ntfs(self.source)
        additions = {20:independent_record(20,'other',directory=True),
                     21:independent_record(21,'first.bin',[independent_resident(0x80,b'sibling')],parent=20)}
        for number,record in additions.items():
            image[4*4096+number*1024:4*4096+(number+1)*1024] = record
        self.source.write_bytes(image)
        report = self.recover()
        first,second = self.file_row(report,17),self.file_row(report,21)
        self.assertIn('/folder/first.bin',first['paths'])
        self.assertIn('/other/first.bin',second['paths'])
        self.assertNotEqual(first['output'],second['output'])

    def test_cancellation_keeps_exact_prefix_and_reports_cancelled(self):
        from recover_vhdx_files import RawReader
        independent_ntfs(self.source)
        stop = [False]
        original = RawReader.read_at
        def read(reader,offset,length):
            data = original(reader,offset,length)
            if offset == 40*4096:
                stop[0] = True
            return data
        with patch.object(RawReader,'read_at',read):
            report = self.recover(chunk_size=4096,cancel=lambda:stop[0])
        row = self.file_row(report,17)
        self.assertEqual(report['scan_status'],'cancelled')
        self.assertEqual(row['status'],'partial')
        self.assertEqual(row['size'],4096)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096)

    def test_invalid_fragment_run_is_rejected_not_read_as_content(self):
        image = independent_ntfs(self.source)
        bad = independent_record(17,'first.bin',[independent_nonresident([(1,-1),(1,2)],8192)],parent=16)
        image[4*4096+17*1024:4*4096+18*1024] = bad
        self.source.write_bytes(image)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertNotEqual(row['status'],'recovered')
        self.assertNotIn('output',row)
        self.assertEqual(self.file_row(report,18)['status'],'recovered')

    def test_sparse_unit_four_is_not_misclassified_as_compression(self):
        image = independent_ntfs(self.source)
        attr = independent_nonresident([(1,40),(1,None)],8192,flags=0x8000)
        struct.pack_into('<H',attr,34,4)
        record = independent_record(17,'first.bin',[attr],parent=16)
        image[4*4096+17*1024:4*4096+18*1024] = record
        self.source.write_bytes(image)
        report = self.recover()
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',row)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096+b'\0'*4096)

    def test_empty_nonresident_stream_preserves_empty_file(self):
        image = independent_ntfs(self.source)
        record = independent_record(18,'empty.bin',[independent_nonresident([],0)],parent=16)
        image[4*4096+18*1024:4*4096+19*1024] = record
        self.source.write_bytes(image)
        report = self.recover()
        row = self.file_row(report,18)
        self.assertEqual(row['status'],'recovered',row)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'')
        self.assertEqual(row['size'],0)

    def test_valid_vhdx_wrapper_recovers_same_fragmented_bytes(self):
        from recover_vhdx_files import recover
        payload = independent_ntfs(self.source)
        container = self.root/'disk.vhdx'
        image = make_container(container,states={0:(6,4*MIB)})
        image[4*MIB:4*MIB+len(payload)] = payload
        container.write_bytes(image)
        report = recover(container,self.root/'out',partition_offset=0,partition_size=len(payload))
        row = self.file_row(report,17)
        self.assertEqual(row['status'],'recovered',report)
        self.assertEqual((self.root/'out'/row['output']).read_bytes(),b'A'*4096+b'B'*4096)


class IndependentSessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root/'disk.raw'
        independent_ntfs(self.source)
        self.session = self.root/'session.sqlite'

    def scan(self, **kwargs):
        from revivex_scan_session import scan_source
        return scan_source(self.source,self.session,**kwargs)

    def test_forged_candidate_original_name_is_rejected(self):
        from revivex_scan_session import ScanSession,LazyExporter
        self.scan()
        with ScanSession(self.session) as db:
            row = next(item for item in db.iter_candidates() if item['record_number']==17)
            metadata = json.loads(db.db.execute('SELECT metadata FROM candidates WHERE candidate_id=?',(row['candidate_id'],)).fetchone()[0])
            metadata['file_names'][0]['name'] = 'forged-original.bin'
            metadata['name'] = 'forged-original.bin'
            with db.db:
                db.db.execute('UPDATE candidates SET metadata=? WHERE candidate_id=?',(json.dumps(metadata),row['candidate_id']))
        with LazyExporter(self.session) as exporter:
            with self.assertRaises(ValueError):
                exporter.export_candidate(row['candidate_id'],self.root/'forged')
        self.assertFalse((self.root/'forged').exists())

    def test_out_of_range_committed_cursor_cannot_skip_all_records(self):
        from revivex_scan_session import ScanSession
        self.scan()
        with ScanSession(self.session) as db:
            with db.db:
                db.db.execute('UPDATE cursors SET next_record=999')
                db.db.execute('DELETE FROM candidates')
        with self.assertRaises(ValueError):
            self.scan(resume=True)

    def test_process_crash_rolls_back_rows_and_cursor_together(self):
        from revivex_scan_session import ScanSession
        self.scan()
        code = 'import sqlite3,os; db=sqlite3.connect(%r); db.execute("DELETE FROM candidates"); db.execute("UPDATE cursors SET next_record=999"); os._exit(0)' % str(self.session)
        subprocess.run([sys.executable,'-c',code],check=True)
        with ScanSession(self.session) as db:
            self.assertEqual(db.cursor('0'),32)
            self.assertEqual(db.summary()['counts']['candidates'],2)
        self.scan(resume=True)

    def test_twenty_four_mib_fragmented_export_is_chunked_and_hash_equal(self):
        from recover_vhdx_files import RawReader
        from revivex_scan_session import ScanSession,LazyExporter
        image = independent_ntfs(self.source)
        size = 64*MIB
        struct.pack_into('<Q',image,40,size//512)
        attr = independent_nonresident([(2048,1024),(2048,5120),(2048,-3072)],24*MIB)
        rec = independent_record(17,'large.bin',[attr],parent=16)
        image[4*4096+17*1024:4*4096+18*1024] = rec
        self.source.write_bytes(image)
        expected = hashlib.sha256()
        with self.source.open('r+b') as stream:
            sparse_truncate(stream, size, temporary_root=self.root)
            stream.seek(size-512);stream.write(image[:512])
            for offset,value in ((4*MIB,b'A'),(24*MIB,b'B'),(12*MIB,b'C')):
                stream.seek(offset)
                block = value*MIB
                for _ in range(8):
                    stream.write(block);expected.update(block)
        self.scan()
        with ScanSession(self.session) as db:
            candidate = next(row for row in db.iter_candidates() if row['record_number']==17)
        calls = []
        original = RawReader.read_at
        def spy(reader,offset,length):
            calls.append((offset,length))
            return original(reader,offset,length)
        tracemalloc.start()
        try:
            with patch.object(RawReader,'read_at',spy),LazyExporter(self.session,chunk_size=512*1024) as exporter:
                outcome = exporter.export_candidate(candidate['candidate_id'],self.root/'large-export.bin')
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertEqual(outcome['size'],24*MIB)
        self.assertEqual(outcome['sha256'],expected.hexdigest())
        actual = hashlib.sha256()
        with (self.root/'large-export.bin').open('rb') as stream:
            for block in iter(lambda:stream.read(MIB),b''):
                actual.update(block)
        self.assertEqual(actual.hexdigest(),expected.hexdigest())
        self.assertLessEqual(max(length for _,length in calls),512*1024)
        self.assertLess(peak,24*MIB)
        self.assertEqual(outcome['original_content_integrity'],'unknown')

    def test_source_change_with_restored_mtime_and_option_drift_rejected(self):
        from revivex_scan_session import LazyExporter
        self.scan()
        with self.assertRaises(ValueError):
            self.scan(resume=True,options={'include_system':True})
        original_stat = self.source.stat()
        with self.source.open('r+b') as stream:
            stream.seek(40*4096);stream.write(b'changed')
        os.utime(self.source,ns=(original_stat.st_atime_ns,original_stat.st_mtime_ns))
        with self.assertRaises(ValueError):
            self.scan(resume=True)
        with self.assertRaises(ValueError):
            LazyExporter(self.session)

    def test_last_lazy_selection_cancel_is_reported_as_cancelled(self):
        from recover_vhdx_files import RawReader
        from revivex_scan_session import ScanSession,LazyExporter
        from revivex_catalog import RecoveryCatalog
        self.scan()
        with ScanSession(self.session) as db:
            row = next(item for item in db.iter_candidates() if item['record_number']==17)
        row.update(status='logical_candidate',integrity='indexed: validated logical mapping; bytes not yet recovered',
                   size=row['expected_size'],session_path=str(self.session))
        stop = threading.Event()
        original_read,original_init = RawReader.read_at,LazyExporter.__init__
        def read(reader,offset,length):
            data = original_read(reader,offset,length)
            if offset == 40*4096:
                stop.set()
            return data
        def init(exporter,*args,**kwargs):
            kwargs['chunk_size']=1024
            original_init(exporter,*args,**kwargs)
        with RecoveryCatalog(self.root/'catalog.sqlite') as cat:
            cat.ingest('source',[row],source_path=str(self.source))
            cat.select_filtered()
            with patch.object(RawReader,'read_at',read),patch.object(LazyExporter,'__init__',init):
                result = cat.export_selected(self.root/'export',cancel_event=stop)
        self.assertTrue(result['cancelled'],result)

    def test_lazy_catalog_create_race_preserves_unowned_file(self):
        from revivex_scan_session import ScanSession,LazyExporter
        from revivex_catalog import RecoveryCatalog
        self.scan()
        with ScanSession(self.session) as db:
            row = next(item for item in db.iter_candidates() if item['record_number']==18)
        row.update(status='logical_candidate',integrity='indexed: validated logical mapping; bytes not yet recovered',
                   size=row['expected_size'],session_path=str(self.session))
        original = LazyExporter.export_candidate
        raced = []
        def race(exporter,candidate_id,destination):
            destination.write_bytes(b'unowned concurrent output')
            raced.append(destination)
            return original(exporter,candidate_id,destination)
        with RecoveryCatalog(self.root/'catalog.sqlite') as cat:
            cat.ingest('source',[row],source_path=str(self.source));cat.select_filtered()
            with patch.object(LazyExporter,'export_candidate',race):
                result = cat.export_selected(self.root/'export')
        self.assertEqual(result['failed'],1,result)
        self.assertEqual(raced[0].read_bytes(),b'unowned concurrent output')

    def test_lazy_catalog_cancel_exception_without_event_is_cancelled(self):
        from recover_vhdx_files import Cancelled
        from revivex_scan_session import ScanSession,LazyExporter
        from revivex_catalog import RecoveryCatalog
        self.scan()
        with ScanSession(self.session) as db:
            row = next(item for item in db.iter_candidates() if item['record_number']==18)
        row.update(status='logical_candidate',integrity='indexed: validated logical mapping; bytes not yet recovered',
                   size=row['expected_size'],session_path=str(self.session))
        with RecoveryCatalog(self.root/'catalog.sqlite') as cat:
            cat.ingest('source',[row],source_path=str(self.source));cat.select_filtered()
            with patch.object(LazyExporter,'export_candidate',side_effect=Cancelled('Synthetic cancellation')):
                result = cat.export_selected(self.root/'export')
        self.assertTrue(result['cancelled'],result)

    def test_large_sparse_metadata_only_and_selected_resident_no_payload_read(self):
        from recover_vhdx_files import RawReader
        from revivex_scan_session import ScanSession,LazyExporter
        image = independent_ntfs(self.source)
        volume_size,stream_size = 16*1024**3,8*1024**3
        struct.pack_into('<Q',image,40,volume_size//512)
        attr = independent_nonresident([(stream_size//4096,None)],stream_size,flags=0x8000)
        rec = independent_record(17,'huge.bin',[attr],parent=16)
        image[4*4096+17*1024:4*4096+18*1024] = rec
        self.source.write_bytes(image)
        with self.source.open('r+b') as stream:
            sparse_truncate(stream, volume_size, temporary_root=self.root)
            stream.seek(volume_size-512);stream.write(image[:512])
        calls = []
        original = RawReader.read_at
        def spy(reader,offset,length):
            calls.append((offset,length))
            return original(reader,offset,length)
        with patch.object(RawReader,'read_at',spy):
            self.scan()
            with ScanSession(self.session) as db:
                rows = list(db.iter_candidates())
            huge = next(row for row in rows if row['record_number']==17)
            tiny = next(row for row in rows if row['record_number']==18)
            self.assertEqual(huge['expected_size'],stream_size)
            with LazyExporter(self.session) as exporter:
                exporter.export_candidate(tiny['candidate_id'],self.root/'tiny')
        self.assertEqual((self.root/'tiny').read_bytes(),b'hello')
        self.assertLess(sum(length for _,length in calls),128*1024)
        self.assertFalse(any(offset>=40*4096 for offset,length in calls))


if __name__ == '__main__':
    unittest.main()
