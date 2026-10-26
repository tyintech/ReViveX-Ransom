from sparse_fixtures import sparse_truncate
import json
import tempfile
import os
import struct
import subprocess
import sys
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from recover_vhdx_files import Cancelled, RawReader
from revivex_scan_session import ScanSession, scan_source, LazyExporter
from test_recover_vhdx_files import ntfs_fixture, CLUSTER


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'disk.raw'
        data, self.payload = ntfs_fixture()
        self.source.write_bytes(data)
        self.session = self.root / 'session.sqlite'

    def tearDown(self):
        self.temp.cleanup()

    def test_metadata_only_and_selected_nonresident_reads(self):
        reads = []
        original = RawReader.read_at
        def spy(reader, offset, length):
            reads.append((offset, length))
            return original(reader, offset, length)
        with patch.object(RawReader, 'read_at', spy):
            summary = scan_source(self.source, self.session, batch_size=4)
        self.assertEqual(summary['status'], 'finished')
        self.assertFalse(any(o <= 40 * CLUSTER < o + n for o,n in reads))
        with ScanSession(self.session) as db:
            rows = list(db.iter_candidates())
            self.assertEqual(len(rows), 3)
            main = next(r for r in rows if not r['stream_name'] and r['record_number'] == 17)
            ads = next(r for r in rows if r['stream_name'])
            self.assertEqual(main['relative_path'], 'Documents/report.bin')
        reads.clear()
        with patch.object(RawReader, 'read_at', spy), LazyExporter(self.session) as exporter:
            result = exporter.export_candidate(ads['candidate_id'], self.root / 'ads')
        self.assertEqual((self.root / 'ads').read_bytes(), b'named stream')
        self.assertFalse(any(o <= 40 * CLUSTER < o + n for o,n in reads))
        with LazyExporter(self.session, chunk_size=1031) as exporter:
            result = exporter.export_candidate(main['candidate_id'], self.root / 'nested/Documents/report.bin')
        self.assertEqual((self.root / 'nested/Documents/report.bin').read_bytes(), self.payload)
        self.assertEqual(result['status'], 'recovered')

    def test_interrupt_resume_idempotence_options_and_source_drift(self):
        calls = 0
        def cancel():
            nonlocal calls
            calls += 1
            return calls == 20
        with self.assertRaises(Cancelled):
            scan_source(self.source, self.session, batch_size=4, cancel=cancel)
        with ScanSession(self.session) as db:
            self.assertEqual(db.cursor('0'), 16)
        scan_source(self.source, self.session, resume=True, batch_size=4)
        with ScanSession(self.session) as db:
            before = db.summary()['counts']
        scan_source(self.source, self.session, resume=True, batch_size=4)
        with ScanSession(self.session) as db:
            self.assertEqual(before, db.summary()['counts'])
        with self.assertRaisesRegex(ValueError, 'options mismatch'):
            scan_source(self.source, self.session, resume=True, options={'include_system': True})
        with self.source.open('r+b') as f:
            f.seek(40 * CLUSTER); f.write(b'changed')
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            scan_source(self.source, self.session, resume=True)

    def test_atomic_conflicting_overlap_and_checkpoint(self):
        scan_source(self.source, self.session)
        with ScanSession(self.session) as db:
            before = db.summary()['counts']
            meta = db.get_record('0', 17)
            db.commit_batch('0', 20, [(17,meta)], [])
            self.assertEqual(db.cursor('0'), 32)
            bad = dict(meta, sequence=99)
            with self.assertRaisesRegex(ValueError, 'Conflicting'):
                db.commit_batch('0', 100, [(99,meta),(17,bad)], [])
            self.assertIsNone(db.get_record('0',99))
            self.assertEqual(db.cursor('0'),32)
            self.assertEqual(before,db.summary()['counts'])

    def test_no_overwrite_or_descriptor_tampering(self):
        scan_source(self.source, self.session)
        with ScanSession(self.session) as db:
            row = next(db.iter_candidates())
        destination = self.root / 'saved'; destination.write_bytes(b'original')
        with LazyExporter(self.session) as exporter:
            with self.assertRaises(FileExistsError):
                exporter.export_candidate(row['candidate_id'], destination)
        self.assertEqual(destination.read_bytes(),b'original')
        with ScanSession(self.session) as db:
            attr = json.loads(db.db.execute('SELECT attribute FROM candidates WHERE candidate_id=?',(row['candidate_id'],)).fetchone()[0])
            attr['raw_hex'] = '00'
            with db.db:
                db.db.execute('UPDATE candidates SET attribute=? WHERE candidate_id=?',(json.dumps(attr),row['candidate_id']))
        with LazyExporter(self.session) as exporter:
            with self.assertRaisesRegex(ValueError, 'attribute differs'):
                exporter.export_candidate(row['candidate_id'], self.root/'tampered')
        self.assertFalse((self.root/'tampered').exists())

    def test_failed_read_keeps_partial_outcome_without_zeros(self):
        scan_source(self.source,self.session)
        with ScanSession(self.session) as db:
            row=next(r for r in db.iter_candidates() if not r['stream_name'])
        original=RawReader.read_at
        def bad(reader,offset,length):
            if offset >= 50*CLUSTER and offset < 52*CLUSTER:
                raise OSError('unreadable range')
            return original(reader,offset,length)
        with LazyExporter(self.session,chunk_size=1024) as exporter:
            with patch.object(RawReader,'read_at',bad),self.assertRaises(OSError):
                exporter.export_candidate(row['candidate_id'],self.root/'partial')
        actual=(self.root/'partial').read_bytes()
        self.assertEqual(actual,self.payload[:len(actual)])
        self.assertLess(len(actual),len(self.payload))
        with ScanSession(self.session) as db:
            outcome=json.loads(db.db.execute('SELECT metadata FROM outcomes').fetchone()[0])
        self.assertEqual(outcome['status'],'partial')
        self.assertEqual(outcome['size'],len(actual))


    def test_partial_bat_opt_in_and_resume_option_identity(self):
        from vhdx_fixtures import build_vhdx, MB
        data,_=ntfs_fixture()
        vhdx=self.root/'partial.vhdx'
        build_vhdx(vhdx,data+bytes(MB))
        healthy=self.root/'healthy.sqlite'
        scan_source(vhdx,healthy,options={'allow_partial_bat':True})
        with self.assertRaisesRegex(ValueError,'mismatch'):
            scan_source(vhdx,healthy,resume=True)
        with vhdx.open('r+b') as f:
            f.seek(2*MB+8); f.write(struct.pack('<Q',7))
        with self.assertRaises((ValueError,OSError)):
            scan_source(vhdx,self.root/'strict.sqlite')
        result=scan_source(vhdx,self.root/'partial.sqlite',options={'allow_partial_bat':True})
        self.assertEqual(result['status'],'finished_with_errors')
        self.assertTrue(result['source_mapping']['partial_bat'])
        self.assertFalse(result['source_mapping']['logical_mapping_complete'])
        self.assertEqual(result['counts']['candidates'],3)
        with self.assertRaisesRegex(ValueError,'only valid for VHDX'):
            scan_source(self.source,self.root/'raw_partial.sqlite',options={'allow_partial_bat':True})

    def test_tampered_parent_and_schema_are_rejected(self):
        scan_source(self.source,self.session)
        with ScanSession(self.session) as db:
            row=next(r for r in db.iter_candidates() if r['record_number']==17)
            parent=db.get_record('0',16)
            parent['file_names'][0]['name']='forged'
            with db.db:
                db.db.execute('UPDATE records SET metadata=? WHERE volume_id=? AND number=?',(json.dumps(parent),'0',16))
        with LazyExporter(self.session) as exporter:
            with self.assertRaisesRegex(OSError,'parent metadata differs'):
                exporter.export_candidate(row['candidate_id'],self.root/'forged')
        with ScanSession(self.session) as db:
            db.db.execute('CREATE TRIGGER malicious AFTER INSERT ON outcomes BEGIN DELETE FROM records; END')
        with self.assertRaisesRegex(ValueError,'schema objects'):
            ScanSession(self.session)

    def test_deep_verified_parent_chain_is_preserved(self):
        from test_recover_vhdx_files import record, filename, nonresident
        data=bytearray(self.source.read_bytes())
        mft=bytearray(128*1024)
        mft[:1024]=record(0,[filename('$MFT'),nonresident([(4,16),(20,16)],len(mft))])
        mft[5*1024:6*1024]=record(5,[filename('.')],flags=3)
        parent=5
        names=[]
        for number in range(16,96):
            name='level'+str(number)
            names.append(name)
            mft[number*1024:(number+1)*1024]=record(number,[filename(name,parent=parent)],flags=3)
            parent=number
        mft[96*1024:97*1024]=record(96,[filename('report.bin',parent=parent),nonresident([(40,2),(50,2)],len(self.payload))])
        data[4*CLUSTER:36*CLUSTER]=mft
        self.source.write_bytes(data)
        scan_source(self.source,self.session)
        with ScanSession(self.session) as db:
            row=next(db.iter_candidates())
            self.assertEqual(row['relative_path'],'/'.join(names+['report.bin']))
        destination=self.root/'export'/row['relative_path']
        with LazyExporter(self.session) as exporter:
            exporter.export_candidate(row['candidate_id'],destination)
        self.assertEqual(destination.read_bytes(),self.payload)

    def test_crash_uncommitted_batch_rolls_back(self):
        scan_source(self.source, self.session)
        code = "import sqlite3,os; db=sqlite3.connect(%r); db.execute(\"UPDATE cursors SET next_record=999\"); db.execute(\"DELETE FROM candidates\"); os._exit(0)" % str(self.session)
        subprocess.run([sys.executable, '-c', code], check=True)
        with ScanSession(self.session) as db:
            self.assertEqual(db.cursor('0'), 32)
            self.assertEqual(db.summary()['counts']['candidates'], 3)
        scan_source(self.source, self.session, resume=True)

    def test_cli_resume_copies_wal_safe_session(self):
        scan_source(self.source,self.session)
        output=self.root/'continued'
        result=subprocess.run([sys.executable,'-m','revivex_scan_session',str(self.source),str(output),'--resume-session',str(self.session)],capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        summary=json.loads((output/'recovery_manifest.json').read_text())
        self.assertEqual(summary['session_path'],str(output/'session.sqlite'))
        with ScanSession(output/'session.sqlite') as db:
            self.assertEqual(db.summary()['counts']['candidates'],3)

    def test_one_tb_vhdx_large_sparse_file_metadata_bounded(self):
        from vhdx_fixtures import build_vhdx, MB
        from test_recover_vhdx_files import record, filename, nonresident, resident
        from revivex_vhdx import VHDXReader
        data,_=ntfs_fixture()
        data=bytearray(data)
        tb=1024**4
        struct.pack_into('<Q',data,40,tb//512)
        large=record(17,[filename('huge.bin',parent=16),nonresident([(None,tb//2//CLUSTER)],tb//2,flags=0x8000),resident(0x80,b'tiny',name='note',ident=3)])
        # Slot 17 is in the second MFT fragment, LCN20 plus 1 KiB.
        data[20*CLUSTER+1024:20*CLUSTER+2048]=large
        vhdx=self.root/'large.vhdx'
        build_vhdx(vhdx,data)
        block=256*MB
        ratio=(2**23*512)//block
        count=tb//block
        with vhdx.open('r+b') as f:
            f.seek(3*MB+65536); f.write(struct.pack('<I',block))
            f.seek(3*MB+65544); f.write(struct.pack('<Q',tb))
            for i in range(1,count):
                f.seek(2*MB+8*(i+i//ratio)); f.write(struct.pack('<Q',2))
            sparse_truncate(f, 4*MB+block, temporary_root=self.root)
        reads=[]
        original=VHDXReader.read_at
        def spy(reader,offset,length):
            reads.append((offset,length))
            return original(reader,offset,length)
        tracemalloc.start()
        try:
            with patch.object(VHDXReader,'read_at',spy):
                scan_source(vhdx,self.root/'large.sqlite')
            peak=tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak,16*MB)
        self.assertLess(sum(n for _,n in reads),128*1024)
        with ScanSession(self.root/'large.sqlite') as db:
            huge=next(r for r in db.iter_candidates() if r['record_number']==17 and not r['stream_name'])
            tiny=next(r for r in db.iter_candidates() if r['stream_name']=='note')
            self.assertEqual(huge['expected_size'],tb//2)
        with LazyExporter(self.root/'large.sqlite') as exporter:
            exporter.export_candidate(tiny['candidate_id'],self.root/'tiny')
        self.assertEqual((self.root/'tiny').read_bytes(),b'tiny')


if __name__ == '__main__':
    unittest.main()
