"""Synthetic acceptance cases for independent ZIP metadata evidence."""
import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch
from salvage_zip import main, stored_descriptor


def run(data):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);source=root/'input.bin';source.write_bytes(data)
        with patch('sys.argv',['salvage_zip',str(source),str(root/'out'),'--preserve-duplicates']),contextlib.redirect_stdout(io.StringIO()):main()
        report=json.loads((root/'out/_salvage_manifest.json').read_text())
        payloads={r['name']:(root/('out_nested' if r['output_root']=='nested' else 'out')/r['output']).read_bytes()
                  for r in report['records'] if r['status']=='recovered'}
        return report,payloads


class CentralFallbackTests(unittest.TestCase):
    def archive(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w',zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('intact.txt',b'intact payload'*100)
        return bytearray(stream.getvalue())

    def test_damaged_local_signature_recovered(self):
        data=self.archive();data[0:4]=b'BAD!'
        report,payloads=run(data)
        self.assertEqual(report['recovered_files'],1)
        self.assertEqual(payloads['intact.txt'],b'intact payload'*100)

    def test_damaged_local_lengths_recovered_by_adjacent_boundary(self):
        data=self.archive();data[26:30]=b'\xff'*4
        report,payloads=run(data)
        self.assertEqual(report['recovered_files'],1)
        self.assertEqual(report['records'][0]['metadata_evidence'],'central_directory_adjacent_boundary')
        self.assertEqual(payloads['intact.txt'],b'intact payload'*100)

    def test_bad_central_crc_does_not_discard_valid_local_member(self):
        data=self.archive();offset=data.index(b'PK\x01\x02');data[offset+16]^=1
        report,payloads=run(data)
        self.assertEqual(report['recovered_files'],1)
        self.assertTrue(report['records'][0]['central_metadata_conflict'])
        self.assertEqual(payloads['intact.txt'],b'intact payload'*100)

    def test_corrupt_content_never_rescued_by_metadata(self):
        data=self.archive();data[45]^=255
        report,_=run(data)
        self.assertEqual(report['recovered_files'],0)

    def test_unsigned_descriptor_before_next_local_header(self):
        payload=b'legitimate bytes'
        data=payload+struct.pack('<III',zlib.crc32(payload),len(payload),len(payload))+b'PK\x03\x04'+bytes(30)
        self.assertEqual(stored_descriptor(data,0,1024)[0],payload)

    def test_unsigned_zip64_descriptor_at_eof(self):
        payload=b'legitimate bytes'
        data=payload+struct.pack('<IQQ',zlib.crc32(payload),len(payload),len(payload))
        self.assertEqual(stored_descriptor(data,0,1024,True)[0],payload)

    def test_empty_and_nested_directories_are_explicit(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as archive:
            archive.writestr('outer/empty/',b'')
            archive.writestr('outer/other/item.txt',b'one')
            archive.writestr('sibling/item.txt',b'two')
        report,payloads=run(stream.getvalue())
        directories=[r for r in report['files'] if r['status']=='directory']
        self.assertEqual(directories[0]['output'],'outer/empty')
        self.assertEqual(directories[0]['entry_kind'],'directory')
        self.assertEqual(len(payloads),2)
