"""Persistent source-scoped recovery selection and defensive selected-only export.

A copied-and-verified staging file is not necessarily an intact original file.
The export report deliberately records those two facts separately.
"""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import errno
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import sqlite3
import stat
import time
import uuid


FILE_ELIGIBLE_SQL = "(status IN ('recovered','staged','usable','needs_review','suspect_damaged','thumbnail_cache','deleted_usable','deleted_needs_review','deleted_suspect_damaged','deleted_thumbnail_cache') AND integrity LIKE 'verified:%' AND output<>'' AND length(expected_sha256)=64 AND expected_sha256 NOT GLOB '*[^0-9a-fA-F]*')"
ELIGIBLE_SQL = "(" + FILE_ELIGIBLE_SQL + " OR (status='logical_candidate' AND integrity='indexed: validated logical mapping; bytes not yet recovered') OR (status='directory' AND integrity='verified: directory metadata only'))"


class RecoveryCatalog:
    def __init__(self, db_path):
        if str(db_path) != ':memory:':
            _no_symlinks(db_path)
        self.db_path = str(db_path)
        self.db = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.create_function('casefold',1,lambda text: str(text).casefold(),deterministic=True)
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS run_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,label TEXT,path TEXT);
        CREATE TABLE IF NOT EXISTS files(
          id TEXT PRIMARY KEY,source_id TEXT NOT NULL,name TEXT NOT NULL,
          relative_path TEXT NOT NULL,folder TEXT NOT NULL,type_group TEXT NOT NULL,
          output TEXT NOT NULL,size INTEGER NOT NULL,path_reliability TEXT,
          integrity TEXT,status TEXT,validation TEXT,provenance TEXT NOT NULL,
          expected_sha256 TEXT,selected INTEGER NOT NULL DEFAULT 0);
        CREATE INDEX IF NOT EXISTS files_source_folder ON files(source_id,folder);
        CREATE INDEX IF NOT EXISTS files_source_path ON files(source_id,relative_path,id);
        CREATE INDEX IF NOT EXISTS files_type ON files(type_group);
        CREATE INDEX IF NOT EXISTS files_selected ON files(selected,id);
        ''')

    def set_run_summary(self, summary):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO run_metadata VALUES('summary',?)", (json.dumps(summary, ensure_ascii=True),))

    def run_summary(self):
        row = self.db.execute("SELECT value FROM run_metadata WHERE key='summary'").fetchone()
        return json.loads(row[0]) if row else {}

    def availability(self):
        return dict(candidates=self.count(), verified_available=self.db.execute('SELECT count(*) FROM files WHERE '+FILE_ELIGIBLE_SQL).fetchone()[0],
                    directories=self.count(status='directory'), unavailable=self.count()-self.count(eligible_only=True), original_total=None)

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def ingest(self, source_id, rows, source_label='', source_path=''):
        """Upsert a scan without losing selection. Caller supplies source identity."""
        source_id = str(source_id)
        if not source_id:
            raise ValueError('A nonempty source identity is required')
        n = 0
        with self.db:
            self.db.execute('INSERT INTO sources VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label,path=excluded.path',
                            (source_id, source_label or source_id, str(source_path)))
            for row in rows:
                row = dict(row)
                output = str(row.get('output') or '')
                name = str(row.get('name') or Path(output).name or 'unnamed')
                reliability = str(row.get('path_reliability') or 'unknown')
                group = str(row.get('group') or row.get('type_group') or Path(name).suffix.lower().lstrip('.') or 'other')
                relative = str(row.get('relative_path') or name).replace('\\', '/')
                # This is a display namespace, never an assertion of original location.
                reliability_key = reliability.lower()
                if 'inferred' in reliability_key:
                    relative = 'Inferred path/' + relative.lstrip('/')
                elif reliability_key not in ('logical_verified', 'known', 'archive', 'archive_path', 'confirmed_archive_path', 'archive member path (untrusted metadata)'):
                    relative = 'Unknown path/' + group + '/' + relative.lstrip('/')
                identity = str(row.get('id') or row.get('stable_id') or relative)
                file_id = hashlib.sha256((source_id + '\0' + identity).encode('utf-8', 'surrogatepass')).hexdigest()
                size = max(0, int(row.get('size') or 0))
                provenance = dict(row)
                provenance.update(catalog_source_id=source_id, catalog_identity=identity)
                self.db.execute('''INSERT INTO files(id,source_id,name,relative_path,folder,type_group,output,size,path_reliability,integrity,status,validation,provenance,expected_sha256)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                  name=excluded.name,relative_path=excluded.relative_path,folder=excluded.folder,
                  type_group=excluded.type_group,output=excluded.output,size=excluded.size,
                  path_reliability=excluded.path_reliability,integrity=excluded.integrity,
                  status=excluded.status,validation=excluded.validation,provenance=excluded.provenance,
                  expected_sha256=excluded.expected_sha256''',
                  (file_id,source_id,name,relative,relative.rstrip('/') if row.get('status') == 'directory' else str(PurePosixPath(relative).parent),group,output,size,reliability,
                   str(row.get('integrity') or 'unknown'),str(row.get('status') or 'staged'),
                   json.dumps(row.get('validation'),ensure_ascii=True),json.dumps(provenance,ensure_ascii=True,default=str),
                   row.get('sha256') or row.get('staged_sha256')))
                n += 1
            self.db.execute("UPDATE files SET selected=0 WHERE selected=1 AND NOT "+ELIGIBLE_SQL)
        return n

    @staticmethod
    def _where(search='', group=None, folder=None, source_id=None, selected_only=False, status=None, eligible_only=False, **unused):
        clauses, args = [], []
        if eligible_only:
            clauses.append(ELIGIBLE_SQL)
        if search:
            clauses.append('(instr(casefold(name),casefold(?))>0 OR instr(casefold(relative_path),casefold(?))>0 OR instr(casefold(status),casefold(?))>0)')
            args += [str(search),str(search),str(search)]
        if status is not None:
            clauses.append('status=?'); args.append(str(status))
        if group is not None:
            clauses.append('type_group=?'); args.append(str(group))
        if source_id is not None:
            clauses.append('source_id=?'); args.append(str(source_id))
        if folder is not None and str(folder) not in ('', '.'):
            prefix = str(folder).rstrip('/')
            clauses.append('(folder=? OR substr(folder,1,?)=?)')
            args += [prefix,len(prefix)+1,prefix+'/']
        if selected_only:
            clauses.append('selected=1')
        return (' WHERE '+' AND '.join(clauses) if clauses else ''), args

    @staticmethod
    def _row(row):
        d = dict(row)
        d['group'] = d.pop('type_group')
        d['selected'] = bool(d['selected'])
        d['eligible'] = bool(d['status'] in ('recovered', 'staged') and d['integrity'].startswith('verified:') and d['output'] and re.fullmatch(r'[0-9a-fA-F]{64}', d['expected_sha256'] or ''))
        d['eligible'] = d['eligible'] or (d['status'] == 'directory' and d['integrity'] == 'verified: directory metadata only')
        d['eligible'] = d['eligible'] or (d['status'] == 'logical_candidate' and d['integrity'] == 'indexed: validated logical mapping; bytes not yet recovered')
        d['validation'] = json.loads(d['validation'])
        d['provenance'] = json.loads(d['provenance'])
        return d

    def query(self, search='', group=None, folder=None, offset=0, limit=200, selected_only=False, source_id=None, status=None):
        where,args = self._where(search,group,folder,source_id,selected_only,status)
        return [self._row(r) for r in self.db.execute('SELECT * FROM files'+where+' ORDER BY source_id,relative_path,id LIMIT ? OFFSET ?', args+[max(1,int(limit)),max(0,int(offset))])]

    def count(self, **filters):
        where,args = self._where(**filters)
        return self.db.execute('SELECT count(*) FROM files'+where,args).fetchone()[0]

    def selected_count(self):
        return self.count(selected_only=True)

    def set_selected(self, ids, selected=True):
        with self.db:
            self.db.executemany('UPDATE files SET selected=? WHERE id=?' + (' AND '+ELIGIBLE_SQL if selected else ''), ((int(bool(selected)),str(i)) for i in ids))

    def select_filtered(self, selected=True, **filters):
        if selected:
            filters['eligible_only'] = True
        where,args = self._where(**filters)
        with self.db:
            return self.db.execute('UPDATE files SET selected=?'+where,[int(bool(selected))]+args).rowcount

    def select_folder(self, source_id, folder, selected=True):
        return self.select_filtered(selected,source_id=source_id,folder=folder)

    def groups(self):
        return [dict(group=r[0],count=r[1]) for r in self.db.execute('SELECT type_group,count(*) FROM files GROUP BY type_group ORDER BY type_group')]

    def statuses(self):
        return [dict(status=r[0],count=r[1]) for r in self.db.execute('SELECT status,count(*) FROM files GROUP BY status ORDER BY status')]

    def sources(self):
        return [dict(r) for r in self.db.execute('SELECT * FROM sources ORDER BY label,id')]

    def folders(self, source_id=None, offset=0, limit=200, parent=None):
        """Paginated folder listing; parent requests direct children via SQL."""
        where,args = self._where(source_id=source_id)
        if parent is None:
            sql = 'SELECT source_id,folder AS path,count(*) AS count FROM files'+where+' GROUP BY source_id,folder ORDER BY source_id,folder LIMIT ? OFFSET ?'
            return [dict(r) for r in self.db.execute(sql,args+[limit,offset])]
        prefix = '' if parent in ('','.') else str(parent).rstrip('/')+'/'
        sql = '''WITH candidates AS (SELECT source_id,substr(relative_path || CASE WHEN status='directory' THEN '/' ELSE '' END,?) AS tail FROM files'''+where+(' AND ' if where else ' WHERE ')+'''substr(relative_path,1,?)=?),
        children AS (SELECT source_id,substr(tail,1,instr(tail,'/')-1) AS child FROM candidates WHERE instr(tail,'/')>0)
        SELECT source_id,? || child AS path,count(*) AS count FROM children GROUP BY source_id,child ORDER BY source_id,child LIMIT ? OFFSET ?'''
        return [dict(r) for r in self.db.execute(sql,[len(prefix)+1]+args+[len(prefix),prefix,prefix,limit,offset])]

    def export_selected(self, destination, cancel_event=None, progress=None):
        return export_selected(self,destination,cancel_event,progress)


def _cancelled(event):
    return bool(event and (event.is_set() if hasattr(event,'is_set') else event()))


def _safe_component(value):
    value = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', value).rstrip(' .')
    if not value or value in ('.','..'):
        value = '_'
    if value.split('.')[0].upper() in {'CON','PRN','AUX','NUL',*(f'COM{i}' for i in range(1,10)),*(f'LPT{i}' for i in range(1,10))}:
        value = '_'+value
    if len(value.encode('utf-8')) > 180:
        value = value[:50]+'_'+hashlib.sha256(value.encode()).hexdigest()[:16]
    return value


def _no_symlinks(path):
    path = Path(os.path.abspath(path))
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError(f'Symbolic links are not permitted: {part}')
    return path


@contextmanager
def _snapshot_reader(catalog):
    # A dedicated read transaction pins count, source metadata, and selected rows.
    reader = sqlite3.connect(catalog.db_path, timeout=30)
    reader.row_factory = sqlite3.Row
    if catalog.db_path == ':memory:':
        catalog.db.backup(reader)
    try:
        reader.execute('BEGIN')
        yield reader
    finally:
        reader.rollback()
        reader.close()


def export_error_message(error):
    """Keep filesystem limits explicit; never silently flatten recovered paths."""
    if getattr(error, 'winerror', None) == 206 or getattr(error, 'errno', None) == errno.ENAMETOOLONG:
        return ('Destination path exceeds this filesystem or Windows path limit. '
                'The original hierarchy was not flattened. Choose a shorter destination root '
                'or a filesystem that supports this path; this file was not exported.')
    return str(error)


def export_selected(catalog, destination, cancel_event=None, progress=None):
    """Export a frozen selection into a NEW destination. Never executes payloads.

    Export namespace always has a per-source root. Every component is normalized
    and casefold-allocated, including file-vs-directory conflicts. Report is JSONL
    so the exporter never needs to hold every selected row in memory.
    """
    dest = _no_symlinks(destination)
    if dest.exists():
        raise FileExistsError('Choose a new, nonexistent export destination')
    if not dest.parent.is_dir():
        raise ValueError('Destination parent must already exist')
    with _snapshot_reader(catalog) as reader:
        sources = [dict(r) for r in reader.execute('SELECT * FROM sources ORDER BY label,id')]
        for source in sources:
            if source['path']:
                src = Path(source['path']).absolute()
                if dest == src or src in dest.parents or dest in src.parents:
                    raise ValueError('Destination overlaps a recovery source')
        total, needed = reader.execute('SELECT count(*),coalesce(sum(size + 2*length(provenance) + 4096),0) FROM files WHERE selected=1').fetchone()
        if not total:
            raise ValueError('Select at least one file to recover')
        if shutil.disk_usage(dest.parent).free < needed + 1024*1024:
            raise OSError('Not enough free destination space for selected files and report')
        # Freeze the selected snapshot in a temporary SQLite file, not a Python list.
        dest.mkdir(mode=0o700)
        snapshot_path = dest / '.selection.sqlite'
        snapshot = sqlite3.connect(snapshot_path)
        snapshot.execute('CREATE TABLE queue(payload TEXT)')
        with snapshot:
            for r in reader.execute('SELECT * FROM files WHERE selected=1 ORDER BY source_id,relative_path,id'):
                if _cancelled(cancel_event):
                    break
                snapshot.execute('INSERT INTO queue VALUES(?)',(json.dumps(catalog._row(r),ensure_ascii=True),))
    scan_summary = catalog.run_summary()
    result = {'scan_summary': scan_summary, 'scope': 'selected catalog items only; original content integrity and total unknown', 'destination':str(dest),'report':str(dest/'recovery-report.jsonl'),'total':total,'recovered':0,'directories_created':0,'failed':0,'cancelled':_cancelled(cancel_event),'bytes':0}
    used = {}
    lazy_exporters = {}
    def allocate(parent, raw, key, is_dir):
        parent.mkdir(parents=True,exist_ok=True)
        component = _safe_component(raw)
        directory = used.setdefault(str(parent),{})
        folded = component.casefold()
        base = component
        collision = 0
        while folded in directory and directory[folded] != (key,is_dir):
            collision += 1
            stem,suffix = os.path.splitext(base)
            token = hashlib.sha256((key+'\0'+str(collision)).encode('utf-8')).hexdigest()[:16]
            component = _safe_component(stem+'__'+token+suffix)
            folded = component.casefold()
        directory[folded] = (key,is_dir)
        p = parent/component
        _no_symlinks(p)
        if is_dir:
            p.mkdir(exist_ok=True)
        return p
    labels = {s['id']:s['label'] for s in sources}
    try:
        with open(result['report'],'x',encoding='utf-8') as report:
            report.write(json.dumps({'record':'export','version':1,'created_unix':time.time(),'selection_count':total,'source_manifest':sources,'scan_summary':scan_summary,'scope':'selected catalog items only; original content integrity and total unknown'},ensure_ascii=True)+'\n')
            for (payload,) in snapshot.execute('SELECT payload FROM queue'):
                if _cancelled(cancel_event):
                    result['cancelled'] = True
                    break
                row = json.loads(payload)
                record = {'record':'file','id':row['id'],'source_id':row['source_id'],'original_relative_path':row['relative_path'],'path_reliability':row['path_reliability'],'original_integrity':row['integrity'],'namespace_note':'Hierarchy is retained; filesystem-unsafe names and name collisions may be normalized. Original names and paths remain in this report.','provenance':row['provenance'],'export_status':'error'}
                out = None
                out_created = False
                out_identity = None
                lazy_exporter_used = None
                cancellation_types = (InterruptedError,)
                try:
                    if row['status'] == 'logical_candidate':
                        from revivex_scan_session import LazyExporter
                        from recover_vhdx_files import Cancelled
                        cancellation_types = (InterruptedError, Cancelled)
                        provenance = row['provenance']
                        session_path = _no_symlinks(provenance['session_path'])
                        workspace = Path(catalog.db_path).absolute().parent
                        if workspace not in session_path.parents:
                            raise ValueError('Indexed session must remain inside its workspace')
                        key = str(session_path)
                        if key not in lazy_exporters:
                            lazy_exporters[key] = LazyExporter(session_path, cancel=lambda: _cancelled(cancel_event))
                        parent = allocate(dest, labels.get(row['source_id'],'source')+'__'+hashlib.sha256(row['source_id'].encode()).hexdigest()[:12], row['source_id'],True)
                        pieces = row['relative_path'].replace('\\','/').split('/')
                        for i,piece in enumerate(pieces[:-1]):
                            parent = allocate(parent,piece,'/'.join(pieces[:i+1]),True)
                        out = allocate(parent,pieces[-1] or row['name'],row['id'],False)
                        if out.exists():
                            raise FileExistsError('Destination already exists')
                        lazy_exporter_used = lazy_exporters[key]
                        outcome = lazy_exporter_used.export_candidate(provenance['candidate_id'], out)
                        out_created = getattr(lazy_exporter_used, 'created_output', None) == out
                        out_identity = getattr(lazy_exporter_used, 'created_output_identity', None)
                        verification = hashlib.sha256()
                        with out.open('rb') as check:
                            for block in iter(lambda: check.read(1024*1024), b''):
                                if _cancelled(cancel_event):
                                    raise InterruptedError('Export cancelled')
                                verification.update(block)
                        if outcome['size'] != row['size'] or verification.hexdigest() != outcome['sha256']:
                            raise ValueError('Selected logical export readback verification failed')
                        record.update(export_status='copied-and-verified', output=str(out.relative_to(dest)),
                                      sha256=outcome['sha256'], bytes=outcome['size'],
                                      final_integrity='destination matches selected logical stream; original content authenticity and completeness unknown')
                        result['recovered'] += 1
                        result['bytes'] += outcome['size']
                        report.write(json.dumps(record,ensure_ascii=True)+'\n'); report.flush()
                        if progress:
                            progress(dict(result))
                        continue
                    if row['status'] == 'directory':
                        if row['integrity'] != 'verified: directory metadata only':
                            raise ValueError('Directory metadata is not eligible')
                        parent = allocate(dest, labels.get(row['source_id'],'source')+'__'+hashlib.sha256(row['source_id'].encode()).hexdigest()[:12], row['source_id'],True)
                        pieces = row['relative_path'].replace('\\','/').rstrip('/').split('/')
                        for i, piece in enumerate(pieces):
                            parent = allocate(parent,piece,'/'.join(pieces[:i+1]),True)
                        record.update(export_status='directory-created', entry_kind='directory', output=str(parent.relative_to(dest)), final_integrity='directory metadata only; original completeness unknown')
                        result['directories_created'] += 1
                        report.write(json.dumps(record,ensure_ascii=True)+'\n'); report.flush()
                        if progress:
                            progress(dict(result))
                        continue
                    if not row['integrity'].startswith('verified:'):
                        raise ValueError('File is not verified eligible staging content: '+row['integrity'])
                    if not isinstance(row['expected_sha256'],str) or not re.fullmatch(r'[0-9a-fA-F]{64}',row['expected_sha256']):
                        raise ValueError('Verified staging requires a valid manifest SHA-256 digest')
                    source = _no_symlinks(row['output'])
                    if not row['output'] or not source.is_file():
                        raise FileNotFoundError('Staged recovery bytes are missing')
                    if source == dest or dest in source.parents:
                        raise ValueError('Staging overlaps destination')
                    root = allocate(dest, labels.get(row['source_id'],'source')+'__'+hashlib.sha256(row['source_id'].encode()).hexdigest()[:12], row['source_id'],True)
                    pieces = row['relative_path'].replace('\\','/').split('/')
                    parent = root
                    for i,piece in enumerate(pieces[:-1]):
                        parent = allocate(parent,piece,'/'.join(pieces[:i+1]),True)
                    out = allocate(parent,pieces[-1] or row['name'],row['id'],False)
                    digest = hashlib.sha256(); copied = 0
                    # O_NOFOLLOW blocks last-component staging substitutions.
                    fd = os.open(source,os.O_RDONLY | getattr(os,'O_NOFOLLOW',0))
                    with os.fdopen(fd,'rb') as src, open(out,'xb') as target:
                        out_created = True
                        created_stat = os.fstat(target.fileno())
                        out_identity = (created_stat.st_dev, created_stat.st_ino)
                        before = os.fstat(src.fileno())
                        if not stat.S_ISREG(before.st_mode):
                            raise ValueError('Staging must be a regular file')
                        while True:
                            if _cancelled(cancel_event):
                                raise InterruptedError('Export cancelled')
                            block = src.read(1024*1024)
                            if not block: break
                            target.write(block); digest.update(block); copied += len(block)
                        target.flush(); os.fsync(target.fileno())
                        after = os.fstat(src.fileno())
                    if copied != row['size'] or (before.st_size,before.st_mtime_ns) != (after.st_size,after.st_mtime_ns):
                        raise ValueError('Staged bytes changed or size does not match manifest')
                    sha = digest.hexdigest()
                    if sha.lower() != row['expected_sha256'].lower():
                        raise ValueError('Staged bytes do not match manifest SHA-256')
                    verification = hashlib.sha256()
                    with open(out,'rb') as check:
                        for block in iter(lambda:check.read(1024*1024),b''):
                            if _cancelled(cancel_event): raise InterruptedError('Export cancelled')
                            verification.update(block)
                    if verification.hexdigest() != sha:
                        raise OSError('Destination readback verification failed')
                    record.update(export_status='copied-and-verified',output=str(out.relative_to(dest)),namespace_note='Per-source hierarchy preserved; filesystem-unsafe components and collisions may be renamed. Original path is recorded separately.',sha256=sha,bytes=copied,final_integrity='destination matches staged bytes; original integrity: '+row['integrity'])
                    result['recovered'] += 1; result['bytes'] += copied
                except Exception as exc:
                    record['error'] = export_error_message(exc)
                    if lazy_exporter_used is not None:
                        out_created = getattr(lazy_exporter_used, 'created_output', None) == out
                        out_identity = getattr(lazy_exporter_used, 'created_output_identity', None)
                    if out_created and out is not None and out.exists():
                        try:
                            current = out.lstat()
                            if out_identity is None or (current.st_dev, current.st_ino) != out_identity:
                                raise OSError('Cleanup skipped: destination ownership changed or could not be established')
                            out.unlink()
                        except OSError as cleanup_error:
                            record['cleanup_error'] = str(cleanup_error)
                            record['partial_output'] = str(out.relative_to(dest))
                    if isinstance(exc,cancellation_types) or _cancelled(cancel_event):
                        result['cancelled'] = True
                        record['export_status'] = 'cancelled'
                    else: result['failed'] += 1
                report.write(json.dumps(record,ensure_ascii=True)+'\n'); report.flush()
                if progress:
                    progress(dict(result))
                if result['cancelled']: break
            report.write(json.dumps({'record':'summary',**result},ensure_ascii=True)+'\n')
            report.flush(); os.fsync(report.fileno())
        os.chmod(result['report'],0o444)
    finally:
        for exporter in lazy_exporters.values():
            exporter.close()
        snapshot.close()
        snapshot_path.unlink(missing_ok=True)
    return result
