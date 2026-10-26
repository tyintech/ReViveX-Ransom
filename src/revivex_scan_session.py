"""Durable, bounded-memory NTFS metadata inventory and selected streaming export.

The SQLite file belongs on a healthy destination disk. Identity is stat plus
container/volume/MFT metadata, NOT a full source-content hash. Recovery is salvage;
content authenticity and completeness remain unknown, and no bootable VM is promised.
"""
import argparse
import hashlib
import json
import os
import sqlite3
import struct
from pathlib import Path

from recover_vhdx_files import (RawReader, Volume, partitions, boot_for, open_mft,
    read_at, load_logical_record, stream_for, serialize_attribute, verified_paths,
    Cancelled, UnsupportedNTFS)

SCHEMA = 1
DEFAULTS = dict(source_format='auto', raw_sector_size=512, damaged_ranges=[],
                include_system=False, max_records=None, partition_offset=None, partition_size=None, allow_partial_bat=False)
LIMITATIONS = ['Identity checks source stat and container/NTFS metadata, not every source byte.',
               'Content authenticity and aggregate completeness are unknown.',
               'File salvage does not repair a disk or guarantee a bootable VM.']


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def _safe_path(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink destination or ancestor forbidden')
    return path


def _stat(path):
    from revivex_source_io import change_time_ns
    s = Path(path).stat()
    return dict(size=s.st_size, mtime_ns=s.st_mtime_ns, ctime_ns=s.st_ctime_ns,
                change_ns=change_time_ns(path), device=s.st_dev, inode=s.st_ino)


def _options(options):
    options = options or {}
    if set(options) - set(DEFAULTS):
        raise ValueError('Unknown scan options')
    result = json.loads(_json(dict(DEFAULTS, **options)))
    if result['max_records'] is not None and (not isinstance(result['max_records'], int) or result['max_records'] <= 0):
        raise ValueError('max_records must be positive or null')
    if result['source_format'] not in ('auto', 'vhdx', 'raw') or result['raw_sector_size'] not in (512, 4096):
        raise ValueError('Unsupported source format or sector size')
    if not isinstance(result['allow_partial_bat'], bool):
        raise ValueError('allow_partial_bat must be boolean')
    return result


class Source:
    def __init__(self, path, options):
        self.path = Path(path).resolve()
        self.before = _stat(self.path)
        with self.path.open('rb') as f:
            signature = f.read(8)
        if options['source_format'] == 'vhdx' or options['source_format'] == 'auto' and signature == b'vhdxfile':
            from revivex_vhdx import VHDXReader
            self.disk = VHDXReader(self.path, damaged_ranges=options['damaged_ranges'], allow_partial_bat=options['allow_partial_bat'])
        else:
            if options['allow_partial_bat']:
                raise ValueError('Partial BAT salvage is only valid for VHDX sources')
            self.disk = RawReader(self.path, options['damaged_ranges'], options['raw_sector_size'])
        self.volumes = {}
        try:
            offset, size = options['partition_offset'], options['partition_size']
            if offset is not None:
                size = self.disk.size - offset if size is None else size
                if offset < 0 or size <= 0 or offset + size > self.disk.size:
                    raise ValueError('Partition outside source')
                parts = [dict(offset=offset, size=size, scheme='explicit')]
            else:
                if size is not None:
                    raise ValueError('partition_size requires partition_offset')
                parts = partitions(self.disk)
            descriptors = []
            for index, part in enumerate(parts):
                desc = dict(part, volume_id=str(index))
                try:
                    if part.get('unsupported'):
                        raise UnsupportedNTFS(part['unsupported'])
                    volume = Volume(self.disk, part['offset'], part['size'])
                    boot = boot_for(volume)
                    volume.size = boot['size']
                    mft, length, evidence, origin = open_mft(volume, boot)
                    desc.update(boot=boot, mft=evidence, mft_size=length, **origin)
                    self.volumes[str(index)] = (volume, boot, mft, length)
                except (ValueError, OSError, EOFError) as exc:
                    desc['error'] = str(exc)
                descriptors.append(desc)
            self.identity = dict(path=str(self.path), stat=self.before,
                                 container=self.disk.evidence, volumes=descriptors)
            self.check()
        except BaseException:
            self.disk.close()
            raise

    def check(self):
        if _stat(self.path) != self.before:
            raise ValueError('Source changed; refusing scan/resume/export')

    def close(self):
        self.disk.close()


class ScanSession:
    def __init__(self, path, *, identity=None, options=None):
        self.path = _safe_path(path)
        creating = identity is not None
        if creating:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        elif not self.path.is_file():
            raise ValueError('Session does not exist')
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA trusted_schema=OFF')
        if not creating:
            expected = {'session': ['id','schema_version','identity','options','status'],
                'cursors': ['volume_id','next_record'], 'records': ['volume_id','number','metadata'],
                'candidates': ['candidate_id','volume_id','number','metadata','attribute'],
                'errors': ['volume_id','number','reason'], 'outcomes': ['candidate_id','destination','metadata']}
            objects = self.db.execute("SELECT name,type,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
            if {name for name, _, _ in objects} != set(expected) or any(kind != 'table' or 'VIRTUAL' in sql.upper() for name,kind,sql in objects):
                self.db.close()
                raise ValueError('Unexpected session schema objects')
            for name, columns in expected.items():
                if [r[1] for r in self.db.execute('PRAGMA table_info(' + name + ')')] != columns:
                    self.db.close()
                    raise ValueError('Unexpected session schema columns')
        self.db.execute('PRAGMA cache_size=-2048')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        try:
            if creating:
                self.db.executescript('''
                  CREATE TABLE session (id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER, identity TEXT, options TEXT, status TEXT);
                  CREATE TABLE cursors (volume_id TEXT PRIMARY KEY, next_record INTEGER NOT NULL);
                  CREATE TABLE records (volume_id TEXT, number INTEGER, metadata TEXT, PRIMARY KEY(volume_id,number));
                  CREATE TABLE candidates (candidate_id TEXT PRIMARY KEY, volume_id TEXT, number INTEGER, metadata TEXT, attribute TEXT);
                  CREATE TABLE errors (volume_id TEXT, number INTEGER, reason TEXT, PRIMARY KEY(volume_id,number));
                  CREATE TABLE outcomes (candidate_id TEXT, destination TEXT, metadata TEXT, PRIMARY KEY(candidate_id,destination));
                ''')
                with self.db:
                    self.db.execute('INSERT INTO session VALUES (1,?,?,?,?)', (SCHEMA, _json(identity), _json(options), 'running'))
            row = self.db.execute('SELECT schema_version,identity,options,status FROM session WHERE id=1').fetchone()
            if not row or row[0] != SCHEMA:
                raise ValueError('Unsupported session schema')
            self.identity, self.options, self.status = json.loads(row[1]), json.loads(row[2]), row[3]
        except BaseException:
            self.db.close()
            raise

    def validate(self, source, options):
        if _json(self.identity) != _json(source.identity):
            raise ValueError('Source identity mismatch; start a new session')
        if _json(self.options) != _json(options):
            raise ValueError('Scan options mismatch; start a new session')

    def cursor(self, volume_id):
        row = self.db.execute('SELECT next_record FROM cursors WHERE volume_id=?', (volume_id,)).fetchone()
        return row[0] if row else 0

    def commit_batch(self, volume_id, next_record, records, candidates, errors=()):
        """Rows and exclusive resume cursor commit together, including empty slots.

        Overlapping identical records are idempotent; changed rows abort instead of
        overwriting metadata or silently retaining an incompatible candidate.
        """
        with self.db:
            for number, metadata in records:
                text = _json(metadata)
                old = self.db.execute('SELECT metadata FROM records WHERE volume_id=? AND number=?', (volume_id, number)).fetchone()
                if old and old[0] != text:
                    raise ValueError('Conflicting metadata in checkpoint overlap')
                self.db.execute('INSERT OR IGNORE INTO records VALUES (?,?,?)', (volume_id, number, text))
            for cid, number, metadata, attr in candidates:
                values = (cid, volume_id, number, _json(metadata), _json(attr))
                old = self.db.execute('SELECT * FROM candidates WHERE candidate_id=?', (cid,)).fetchone()
                if old and tuple(old) != values:
                    raise ValueError('Conflicting candidate in checkpoint overlap')
                self.db.execute('INSERT OR IGNORE INTO candidates VALUES (?,?,?,?,?)', values)
            for number, reason in errors:
                self.db.execute('INSERT OR IGNORE INTO errors VALUES (?,?,?)', (volume_id, number, reason))
            cursor = max(next_record, self.cursor(volume_id))
            self.db.execute('INSERT INTO cursors VALUES (?,?) ON CONFLICT(volume_id) DO UPDATE SET next_record=excluded.next_record', (volume_id, cursor))

    def get_record(self, volume_id, number):
        row = self.db.execute('SELECT metadata FROM records WHERE volume_id=? AND number=?', (volume_id, number)).fetchone()
        return json.loads(row[0]) if row else None

    def iter_candidates(self, candidate_ids=None):
        def rows():
            if candidate_ids is None:
                yield from self.db.execute('SELECT candidate_id,volume_id,number,metadata FROM candidates ORDER BY volume_id,number,candidate_id')
            else:
                for cid in candidate_ids:
                    row = self.db.execute('SELECT candidate_id,volume_id,number,metadata FROM candidates WHERE candidate_id=?', (cid,)).fetchone()
                    if not row:
                        raise ValueError('Unknown candidate ID')
                    yield row
        for cid, vid, number, text in rows():
            meta = json.loads(text)
            record = self.get_record(vid, number)
            if record is None or any(meta.get(key) != value for key, value in record.items()):
                raise ValueError('Candidate metadata differs from indexed record')
            expected_name = record['file_names'][0]['name'] if record['file_names'] else 'unnamed'
            if meta.get('name') != expected_name:
                raise ValueError('Candidate name differs from indexed record')
            class Records:
                def get(_, n):
                    return self.get_record(vid, n)
            paths = verified_paths(meta, Records())
            yield dict(meta, **paths, candidate_id=cid,
                relative_path=paths['paths'][0].lstrip('/') if paths['paths'] else None,
                path_reliability='logical_verified' if paths['paths'] else 'unknown',
                provenance=dict(session_path=str(self.path), candidate_id=cid))

    def iter_directories(self):
        for vid, text in self.db.execute('SELECT volume_id,metadata FROM records ORDER BY volume_id,number'):
            meta = json.loads(text)
            if not meta['directory'] or not meta['in_use'] or meta['base_record_reference'] or meta['has_attribute_list'] or meta['has_reparse_point']:
                continue
            class Records:
                def get(_, n):
                    return self.get_record(vid, n)
            paths = verified_paths(meta, Records())
            yield dict(meta, **paths, volume_id=vid, status='directory',
                relative_path=paths['paths'][0].lstrip('/') if paths['paths'] else None,
                path_reliability='logical_verified' if paths['paths'] else 'unknown')

    def iter_errors(self):
        for vid, number, reason in self.db.execute('SELECT volume_id,number,reason FROM errors ORDER BY volume_id,number'):
            yield dict(volume_id=vid, record_number=number, status='unavailable', reason=reason)
        for desc in self.identity['volumes']:
            if 'error' in desc:
                yield dict(volume_id=desc['volume_id'], status='unavailable', reason=desc['error'])

    def summary(self):
        status = self.db.execute('SELECT status FROM session WHERE id=1').fetchone()[0]
        counts = {name: self.db.execute('SELECT count(*) FROM ' + name).fetchone()[0] for name in ('records','candidates','errors','outcomes')}
        return dict(schema='revivex.scan-session', schema_version=SCHEMA, session_path=str(self.path),
                    status=status, counts=counts, source_mapping=self.identity['container'], known_failed_volumes=sum('error' in d for d in self.identity['volumes']), completeness='unknown', content_authenticity='unknown', original_content_integrity='unknown', limitations=LIMITATIONS)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def scan_source(source, session_path, *, options=None, resume=False, cancel=None, progress=None, batch_size=128):
    options = _options(options)
    if not 1 <= batch_size <= 4096:
        raise ValueError('batch_size must be 1..4096')
    src = Source(source, options)
    session = None
    try:
        session = ScanSession(session_path) if resume else ScanSession(session_path, identity=src.identity, options=options)
        session.validate(src, options)
        for vid, (volume, boot, mft, length) in src.volumes.items():
            count = length // boot['record_size']
            limit = min(count, options['max_records']) if options['max_records'] else count
            cursor = session.cursor(vid)
            if not isinstance(cursor, int) or not 0 <= cursor <= limit:
                raise ValueError('Session cursor outside effective MFT bounds')
            while cursor < limit:
                records, candidates, errors = [], [], []
                for number in range(cursor, min(cursor + batch_size, limit)):
                    if cancel and cancel():
                        raise Cancelled('Metadata scan cancelled; committed checkpoints can resume')
                    try:
                        raw = read_at(mft, number * boot['record_size'], boot['record_size'])
                        if raw == bytes(boot['record_size']):
                            continue
                        record, attrs, meta = load_logical_record(raw, number)
                        records.append((number, meta))
                        if number < 16 and not options['include_system']:
                            continue
                        if not meta['in_use'] or meta['base_record_reference'] or meta['has_attribute_list'] or meta['has_reparse_point']:
                            errors.append((number, 'Deleted record, extension, ATTRIBUTE_LIST or reparse point unsupported'))
                            continue
                        if meta['directory']:
                            continue
                        streams = [a for a in attrs if a['kind'] == 0x80]
                        if not streams:
                            errors.append((number, 'Missing DATA stream'))
                        names = [a['name'] for a in streams]
                        for attr in streams:
                            try:
                                if names.count(attr['name']) != 1:
                                    raise UnsupportedNTFS('Duplicate DATA stream names')
                                _, size, evidence = stream_for(attr, volume, boot)
                                cid = f"v{vid}:r{number}:s{meta['sequence']}:a{attr['id']}:o{attr['offset']}"
                                row = dict(meta, **evidence, volume_id=vid, name=meta['file_names'][0]['name'] if meta['file_names'] else 'unnamed', stream_name=attr['name'], attribute_id=attr['id'], attribute_offset=attr['offset'], expected_size=size, status='indexed', content_authenticity='unknown', original_content_integrity='unknown', extent_read_complete=False)
                                candidates.append((cid, number, row, serialize_attribute(attr)))
                            except (ValueError, OSError, EOFError, IndexError, struct.error) as exc:
                                errors.append((number, str(exc)))
                    except (ValueError, OSError, EOFError, IndexError, struct.error) as exc:
                        errors.append((number, str(exc)))
                src.check()
                cursor = min(cursor + batch_size, limit)
                session.commit_batch(vid, cursor, records, candidates, errors)
                if progress:
                    progress(dict(phase='metadata', volume_id=vid, next_record=cursor, total_records=count))
        src.check()
        truncated = any(options['max_records'] and length // boot['record_size'] > options['max_records'] for _, boot, _, length in src.volumes.values())
        status = 'limited' if truncated else 'finished_with_errors' if src.disk.evidence.get('partial_bat') or len(src.volumes) != len(src.identity['volumes']) or session.summary()['counts']['errors'] else 'finished'
        with session.db:
            session.db.execute('UPDATE session SET status=? WHERE id=1', (status,))
        return session.summary()
    except Cancelled:
        if session:
            with session.db:
                session.db.execute("UPDATE session SET status='interrupted' WHERE id=1")
        raise
    finally:
        if session:
            session.close()
        src.close()


class LazyExporter:
    def __init__(self, session_path, source=None, cancel=None, chunk_size=1024**2):
        if not 1 <= chunk_size <= 16 * 1024**2:
            raise ValueError('chunk_size must be 1..16 MiB')
        self.session = ScanSession(session_path)
        self.source = None
        try:
            self.source = Source(source or self.session.identity['path'], self.session.options)
            self.session.validate(self.source, self.session.options)
        except BaseException:
            self.close()
            raise
        self.cancel, self.chunk_size = cancel, chunk_size

    def export_candidate(self, candidate_id, destination_file):
        self.created_output = None
        self.created_output_identity = None
        row = self.session.db.execute('SELECT volume_id,number,metadata,attribute FROM candidates WHERE candidate_id=?', (candidate_id,)).fetchone()
        if not row:
            raise ValueError('Unknown candidate')
        vid, number, text, attr_text = row
        meta, stored = json.loads(text), json.loads(attr_text)
        self.source.check()
        volume, boot, mft, _ = self.source.volumes[vid]
        _, attrs, fresh = load_logical_record(read_at(mft, number * boot['record_size'], boot['record_size']), number)
        expected = self.session.get_record(vid, number)
        if fresh != expected or any(meta.get(key) != value for key, value in fresh.items()):
            raise ValueError('Live MFT record differs from indexed record')
        exporter = self
        class LiveParents:
            def get(_, parent_number):
                indexed = exporter.session.get_record(vid, parent_number)
                if indexed is None:
                    return None
                if not 0 <= parent_number < exporter.source.volumes[vid][3] // boot['record_size']:
                    raise OSError('Indexed parent outside MFT')
                try:
                    _, _, live = load_logical_record(read_at(mft, parent_number * boot['record_size'], boot['record_size']), parent_number)
                except (ValueError, EOFError, IndexError, struct.error) as exc:
                    raise OSError('Cannot validate indexed parent metadata') from exc
                if live != indexed:
                    raise OSError('Indexed parent metadata differs from live MFT')
                return live
        # Validate provenance ancestors too; a local database is not evidence of
        # original names. Unknown chains stay unknown rather than being repaired.
        verified_paths(fresh, LiveParents())
        expected_name = fresh['file_names'][0]['name'] if fresh['file_names'] else 'unnamed'
        if meta.get('name') != expected_name:
            raise ValueError('Candidate name differs from live MFT record')
        matches = [a for a in attrs if serialize_attribute(a) == stored and a['kind'] == 0x80]
        if len(matches) != 1:
            raise ValueError('Live DATA attribute differs from indexed attribute')
        attr = matches[0]
        if meta.get('attribute_id') != attr['id'] or meta.get('attribute_offset') != attr['offset'] or meta.get('stream_name') != attr['name'] or meta.get('volume_id') != vid:
            raise ValueError('Candidate stream identity differs from live DATA attribute')
        stream, size, evidence = stream_for(matches[0], volume, boot)
        if size != meta['expected_size']:
            raise ValueError('Stream size mismatch')
        destination = _safe_path(destination_file)
        destination.parent.mkdir(parents=True, exist_ok=True)
        sha, written = hashlib.sha256(), 0
        outcome = dict(candidate_id=candidate_id, destination=str(destination), status='failed', size=0,
                       expected_size=size, content_authenticity='unknown', original_content_integrity='unknown', extent_read_complete=False, integrity='exported_bytes_only')
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
        self.created_output = destination
        created_stat = os.fstat(fd)
        self.created_output_identity = (created_stat.st_dev, created_stat.st_ino)
        try:
            with os.fdopen(fd, 'wb', buffering=0) as target:
                while written < size:
                    if self.cancel and self.cancel():
                        raise Cancelled('Selected export cancelled')
                    self.source.check()
                    amount = min(self.chunk_size, size - written)
                    initialized = evidence['initialized_size']
                    if written < initialized:
                        amount = min(amount, initialized - written)
                        chunk = stream.read(amount)
                        if len(chunk) != amount:
                            raise OSError('Short NTFS stream read')
                    else:
                        chunk = bytes(amount)  # Explicit NTFS uninitialized tail, not unreadable ranges.
                    count = target.write(chunk)
                    count = count or 0
                    written += count
                    sha.update(chunk[:count])
                    if count != len(chunk):
                        raise OSError('Short destination write')
                target.flush()
                os.fsync(target.fileno())
            self.source.check()
            outcome.update(status='recovered', extent_read_complete=True)
        except BaseException as exc:
            outcome.update(status='partial' if written else 'failed', reason=str(exc))
            raise
        finally:
            outcome.update(size=written, sha256=sha.hexdigest())
            with self.session.db:
                self.session.db.execute('INSERT INTO outcomes VALUES (?,?,?) ON CONFLICT(candidate_id,destination) DO UPDATE SET metadata=excluded.metadata', (candidate_id, str(destination), _json(outcome)))
        return outcome

    def close(self):
        if self.source:
            self.source.close()
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def recover_indexed_record(provenance, destination, cancel_event=None):
    with LazyExporter(provenance['session_path'], cancel=cancel_event.is_set if cancel_event else None) as exporter:
        return exporter.export_candidate(provenance['candidate_id'], destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source')
    parser.add_argument('output')
    parser.add_argument('--resume-session')
    parser.add_argument('--source-format', choices=['auto', 'raw', 'vhdx'], default='auto')
    parser.add_argument('--max-records', type=int)
    parser.add_argument('--allow-partial-bat', action='store_true', help='Opt in to independently validated BAT entries; unknown mappings remain unreadable')
    args = parser.parse_args()
    output = _safe_path(args.output)
    output.mkdir(parents=True, exist_ok=False)
    session_path = output / 'session.sqlite'
    options = dict(source_format=args.source_format, max_records=args.max_records, allow_partial_bat=args.allow_partial_bat)
    if args.resume_session:
        with ScanSession(args.resume_session) as prior:
            src = Source(args.source, _options(options))
            try:
                prior.validate(src, _options(options))
                copied = sqlite3.connect(session_path)
                try:
                    prior.db.backup(copied)
                finally:
                    copied.close()
            finally:
                src.close()
    result = scan_source(args.source, session_path, options=options, resume=bool(args.resume_session))
    with (output / 'recovery_manifest.json').open('x') as f:
        json.dump(result, f, indent=2)
    print(_json(result))


if __name__ == '__main__':
    main()
