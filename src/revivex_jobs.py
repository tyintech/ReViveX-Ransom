"""Isolated, windowed-safe recovery jobs. Scan jobs WRITE staged salvage outputs.

The source is read-only. Cancellation terminates the worker, retains partial
outputs, and reconciles them against available manifests without executing them.
"""
from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass, field
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import traceback

MODULES = {'auto': 'revivex_auto', 'zip': 'salvage_zip', 'carve': 'carve_verified_formats',
           'ntfs': 'recover_vhdx_resident', 'logical_ntfs': 'recover_vhdx_files', 'logical_index': 'revivex_scan_session', 'probe': 'probe_vhdx',
           'pairs': 'analyze_gentlemen_pairs', 'inner': 'recover_inner',
           'verify': 'verify_vhdx_recovery'}
OPTIONS = {
    'auto': {'max_file_mib', 'max_total_mib', 'work_dir', 'resume', 'damaged_range', 'block_size_mib', 'deep_raw',
             'max_scan_bytes', 'reserve_mib', 'route', 'skip_deleted'},
    'zip': {'max_file_mib', 'max_total_mib', 'max_input_mib', 'memory_map', 'preserve_duplicates', 'max_candidates'},
    'carve': {'max_file_mib', 'max_total_mib', 'max_decoded_mib', 'gentlemen'},
    'logical_index': {'source_format', 'max_records', 'resume_session', 'allow_partial_bat'},
    'logical_ntfs': {'max_records', 'max_file_bytes', 'max_total_bytes', 'chunk_size', 'source_format', 'partition_offset', 'partition_size', 'raw_sector_size', 'damaged_range', 'include_system', 'allow_partial_bat'},
    'ntfs': {'max_candidates', 'max_output_bytes', 'max_scan_bytes'},
    'probe': {'full_scan'}, 'pairs': {'pairs'}, 'inner': {'outer_member'},
    'verify': {'manifests', 'original_source', 'max_manifest_bytes'},
}
MANIFEST_NAMES = ('recovery_manifest.json', '_salvage_manifest.json', 'manifest.json', 'carve_manifest.json')

@dataclass
class JobSpec:
    tool: str
    source: str
    output: str
    options: dict = field(default_factory=dict)

@dataclass
class JobResult:
    status: str
    output: str
    rows: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    log: str = ''
    error: str = ''


def _no_symlinks(path):
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('Symlink paths are not accepted')


def validate_spec(spec):
    if spec.tool not in MODULES:
        raise ValueError('Unknown job tool')
    if not isinstance(spec.options, dict) or set(spec.options) - OPTIONS[spec.tool]:
        raise ValueError('Unsupported job options')
    source, output = Path(spec.source).absolute(), Path(spec.output).absolute()
    _no_symlinks(source)
    _no_symlinks(output)
    if not (source.is_dir() if spec.tool == 'verify' else source.is_file()):
        raise ValueError('Source must be a directory for verification or a regular file for other jobs')
    resume = spec.tool == 'auto' and spec.options.get('resume') is True
    if resume:
        _validate_auto_resume(source, output)
    elif output.exists():
        raise ValueError('Output must be a new directory, not an existing or reused directory')
    if spec.tool == 'auto' and spec.options.get('work_dir'):
        work = Path(spec.options['work_dir']).absolute()
        _no_symlinks(work)
        if not work.is_dir():
            raise ValueError('The temporary work folder must be an existing directory')
        if work.resolve() == source.resolve() or source.resolve() in work.resolve().parents:
            raise ValueError('The temporary work folder must not be inside the source')
    if spec.tool == 'auto':
        for key in ('resume', 'deep_raw', 'skip_deleted'):
            if key in spec.options and not isinstance(spec.options[key], bool):
                raise ValueError(f'{key} must be true or false')
        if spec.options.get('route', 'auto') not in ('auto', 'logical', 'rebuild', 'raw'):
            raise ValueError('Unknown automatic-recovery route')
    source, output = source.resolve(), output.resolve()
    if source == output or source in output.parents or output in source.parents:
        raise ValueError('Source and output must be separate')
    for key, value in spec.options.items():
        if key.startswith('max_') and (not isinstance(value, int) or isinstance(value, bool) or value <= 0):
            raise ValueError(f'{key} must be a positive integer')
    if spec.tool == 'inner' and not spec.options.get('outer_member'):
        raise ValueError('Exact outer archive member is required')
    if spec.tool == 'pairs':
        pairs = spec.options.get('pairs', [])
        if not pairs or any(not isinstance(p, (list, tuple)) or len(p) != 2 for p in pairs):
            raise ValueError('At least one original/encrypted file pair is required')
        for pair in pairs:
            for p in pair:
                path = Path(p).absolute()
                _no_symlinks(path)
                if not path.is_file():
                    raise ValueError('Pair input must be a regular file')
    return JobSpec(spec.tool, str(source), str(output), dict(spec.options))


def _validate_auto_resume(source, output):
    """Continue an automatic-recovery job in place: same source, our own workspace."""
    request = output / 'job_request.json'
    if not output.is_dir() or not request.is_file() or not (output / 'payload' / 'auto.sqlite').is_file():
        raise ValueError('Choose a previous automatic-recovery folder to continue')
    _no_symlinks(request)
    previous = json.loads(request.read_text(encoding='utf-8'))
    if previous.get('tool') != 'auto' or Path(previous.get('source', '')).resolve() != source.resolve():
        raise ValueError('That folder belongs to a different source or method; continue requires the same source')


def build_arguments(spec):
    root = Path(spec.output)
    if spec.tool == 'auto':
        args = [spec.source, str(root / 'payload'), '--progress', str(root / 'progress.json'),
                '--cancel-file', str(root / CANCEL_FILE)]
        for key, value in spec.options.items():
            if key == 'resume' or value is None or value is False:
                continue  # an existing payload folder is continued in place
            if key == 'damaged_range':
                for interval in value:
                    args += ['--damaged-range', str(interval)]
            elif value is True:
                args.append('--' + key.replace('_', '-'))
            else:
                args += ['--' + key.replace('_', '-'), str(value)]
        return args
    args = [spec.source]
    if spec.tool in ('zip', 'carve', 'ntfs', 'logical_ntfs', 'logical_index', 'inner'):
        args.append(str(root / 'payload'))
    elif spec.tool == 'pairs':
        args.append(str(root / 'report.json'))
    else:
        args += ['--report', str(root / 'report.json')]
    if spec.tool == 'zip':
        args += ['--nested-output', str(root / 'nested')]
    if spec.tool == 'verify' and not spec.options.get('manifests'):
        workspace = Path(spec.source)
        request = workspace / 'job_request.json'
        if request.is_file():
            previous = _json(request)
            names = {'zip': ('_salvage_manifest.json',), 'ntfs': ('recovery_manifest.json',), 'logical_ntfs': ('recovery_manifest.json',), 'logical_index': ('recovery_manifest.json',),
                     'carve': ('manifest.json',), 'inner': ('manifest.json',)}.get(previous.get('tool'), ())
            for directory in (workspace / 'payload', workspace / 'nested'):
                for name in names:
                    path = directory / name
                    if path.is_file():
                        _no_symlinks(path)
                        args += ['--manifest', str(path)]
    for key, value in spec.options.items():
        if key == 'pairs':
            for pair in value:
                args += ['--pair', *map(str, pair)]
        elif key == 'damaged_range':
            for interval in value:
                args += ['--damaged-range', str(interval)]
        elif key == 'manifests':
            for path in value:
                args += ['--manifest', str(path)]
        elif key == 'original_source':
            args += ['--source', str(value)]
        elif isinstance(value, bool):
            if value:
                args.append('--' + key.replace('_', '-'))
        elif value is not None:
            args += ['--' + key.replace('_', '-'), str(value)]
    return args


def worker_command(config_path, frozen=None):
    """Frozen executable must dispatch --run-job before importing/starting Qt."""
    frozen = getattr(sys, 'frozen', False) if frozen is None else frozen
    prefix = [sys.executable] if frozen else [sys.executable, str(Path(__file__).resolve())]
    return prefix + ['--run-job', str(config_path)]


def dispatch_worker(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] != '--run-job':
        return False
    if len(argv) != 2:
        raise SystemExit(2)
    config = Path(argv[1])
    spec = JobSpec(**json.loads(config.read_text(encoding='utf-8')))
    # Do not run arbitrary module names from serialized requests.
    if spec.tool not in MODULES or set(spec.options) - OPTIONS[spec.tool]:
        raise SystemExit(2)
    root = Path(spec.output)
    code = 0
    with (root / 'worker.log').open('a', encoding='utf-8', buffering=1) as log:
        # Windowed PyInstaller sets sys.stdout/sys.stderr to None. Explicitly
        # assign both streams, and isolate sys.argv changes inside this process.
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            try:
                sys.argv = [MODULES[spec.tool], *build_arguments(spec)]
                returned = importlib.import_module(MODULES[spec.tool]).main()
                code = returned if isinstance(returned, int) else 0
            except SystemExit as error:
                code = error.code if isinstance(error.code, int) else 1
            except BaseException:
                traceback.print_exc()
                code = 1
    raise SystemExit(code)


def _json(path):
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError('Manifest exceeds 64 MiB limit')
    value = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value, dict) or value.get('schema_version', 1) != 1:
        raise ValueError('Unsupported manifest object/version')
    return value


def collect_results(spec, returncode, cancelled=False):
    from verify_vhdx_recovery import digest_file, safe_output
    root = Path(spec.output)
    source = Path(spec.source)
    stat = source.stat()
    source_id = hashlib.sha256(f'{source.resolve()}|{stat.st_size}|{stat.st_mtime_ns}'.encode()).hexdigest()
    from revivex_catalog import RecoveryCatalog
    catalog_path = root / 'catalog.sqlite'
    catalog = RecoveryCatalog(catalog_path)
    rows, manifests, errors, seen = [], [], [], set()
    buffer = []
    diagnostic_keys = set()
    row_count = 0
    integrity_failed = False
    unverified_outputs = False
    def stage(row):
        nonlocal row_count, integrity_failed, unverified_outputs
        row_count += 1
        integrity_failed |= row['integrity'].startswith('failed:')
        unverified_outputs |= row['status'] == 'partial_unverified'
        if row_count <= 1000:
            rows.append(row)
        buffer.append(row)
        if len(buffer) >= 2000:
            catalog.ingest(source_id, buffer, source.name, str(source))
            buffer.clear()
    def diagnostic(entry, origin):
        status = str(entry.get('status') or 'unrecoverable')
        if status in ('recovered', 'verified_duplicate', 'validated_record'):
            return
        key = (origin, entry.get('offset', entry.get('header_offset')), entry.get('attribute_offset'), entry.get('volume_id'), entry.get('record_number'), entry.get('stream_name'), entry.get('name'), status)
        if key in diagnostic_keys:
            return
        diagnostic_keys.add(key)
        name = entry.get('name') or (entry.get('file_names') or [{}])[0].get('name') or f"{entry.get('format', 'candidate')}@{entry.get('offset', entry.get('header_offset', entry.get('record_number', 'unknown')))}"
        directory = status == 'directory'
        display_path = entry.get('relative_path') if directory and entry.get('relative_path') == '' else entry.get('relative_path') or name
        if spec.tool in ('logical_ntfs', 'logical_index') and entry.get('volume_id'):
            display_path = str(entry['volume_id']) + '/' + display_path.lstrip('/')
        stage(dict(id=hashlib.sha256(repr(key).encode()).hexdigest(), name=name,
                   relative_path=display_path,
                   path_reliability=entry.get('path_reliability') or ('archive' if spec.tool == 'zip' else 'name_only'),
                   integrity='verified: directory metadata only' if directory else 'unavailable: '+str(entry.get('error') or entry.get('reason') or status),
                   group='directory' if directory else '', size=0, output='', status=status, validation=entry, manifest=origin))
    manifest_names = {'zip': ('_salvage_manifest.json',), 'ntfs': ('recovery_manifest.json',), 'logical_ntfs': ('recovery_manifest.json',), 'logical_index': ('recovery_manifest.json',),
                      'carve': ('manifest.json',), 'inner': ('manifest.json',)}.get(spec.tool, ())
    safe_directories = []
    for directory in (root / 'payload', root / 'nested'):
        try:
            _no_symlinks(directory)
            safe_directories.append(directory)
        except ValueError as error:
            errors.append(str(directory) + ': ' + str(error))
    ntfs_paths, path_inference_warning = {}, ''
    if spec.tool == 'ntfs' and root / 'payload' in safe_directories:
        try:
            from revivex_ntfs_paths import load_record_paths
            index = root / 'payload' / 'record_index.jsonl'
            _no_symlinks(index)
            ntfs_paths = load_record_paths(index, source_id)
        except (OSError, ValueError, TypeError) as error:
            path_inference_warning = f'Optional NTFS path inference unavailable: {error}'
    for directory in safe_directories:
        for name in manifest_names:
            manifest = directory / name
            if not manifest.is_file():
                continue
            try:
                _no_symlinks(manifest)
                report = _json(manifest)
                manifests.append({'path': str(manifest), **{k: v for k, v in report.items() if k not in ('files', 'records')}})
                entries = report.get('files', report.get('records', []))
                if not isinstance(entries, list):
                    raise ValueError('Manifest entries must be a list')
                for entry in report.get('directories', []):
                    diagnostic({**entry, 'status': 'directory'}, str(manifest))
                for entry in report.get('records', []):
                    if isinstance(entry, dict) and entry.get('status') != 'recovered' and (not entry.get('output_root') or entry['output_root'] == ('nested' if directory.name == 'nested' else 'primary')):
                        diagnostic(entry, str(manifest))
                for entry in entries:
                    if isinstance(entry, dict) and entry.get('status') not in (None, 'recovered'):
                        diagnostic(entry, str(manifest))
                    if not isinstance(entry, dict) or not entry.get('output') or entry.get('status') not in (None, 'recovered'):
                        continue
                    relative = str(entry['output'])
                    integrity, actual_size, target = 'unverified', entry.get('size', 0), ''
                    try:
                        path = safe_output(directory, relative)
                        target = str(path.resolve())
                        if target in seen:
                            continue
                        seen.add(target)
                        actual_size, sha, crc = digest_file(path)
                        if actual_size != entry.get('size') or sha != entry.get('sha256'):
                            integrity = 'failed: size or SHA-256 mismatch'
                        elif entry.get('crc32') and crc != entry['crc32'].lower():
                            integrity = 'failed: CRC-32 mismatch'
                        else:
                            integrity = 'verified: size and SHA-256' + (' and CRC-32' if entry.get('crc32') else '')
                    except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
                        integrity = 'failed: ' + str(error)
                    schema = report.get('schema', '')
                    reliability = 'archive member path (untrusted metadata)' if 'zip' in schema else 'filename only; original folders unknown' if 'ntfs' in schema else 'generated name; original filename and folders unknown'
                    row_path = str(Path(directory.name) / relative)
                    display_path = (entry.get('name') or relative) if 'zip' in schema else row_path
                    path_outcomes, path_reason = [], ''
                    if spec.tool in ('logical_ntfs', 'logical_index'):
                        path_outcomes = entry.get('paths', [])
                        path_reason = entry.get('path_status', '')
                        display_path = entry.get('relative_path') or entry.get('path') or entry.get('name') or row_path
                        if entry.get('volume_id'):
                            display_path = str(entry['volume_id']) + '/' + display_path.lstrip('/')
                        reliability = entry.get('path_reliability', 'name_only')
                    if spec.tool == 'ntfs':
                        path_outcomes = ntfs_paths.get(entry.get('offset'), [])
                        if len(path_outcomes) == 1 and path_outcomes[0].get('path_status') == 'inferred_unverified':
                            display_path = path_outcomes[0]['path'].lstrip('/')
                            reliability = 'inferred_unverified'
                            path_reason = path_outcomes[0]['reason']
                        else:
                            display_path = entry.get('name') or Path(relative).name
                            reliability = 'name_only'
                            path_reason = path_inference_warning or ('multiple_hardlink_or_path_outcomes' if len(path_outcomes) > 1 else path_outcomes[0].get('reason', 'path_unknown') if path_outcomes else 'missing_record_path_metadata')
                    stage(dict(id=hashlib.sha256((source_id + '|' + row_path).encode('utf-8')).hexdigest(), name=entry.get('name') or Path(relative).name,
                                     relative_path=display_path, ntfs_path_outcomes=path_outcomes, ntfs_stream_name=entry.get('stream_name', ''), source_offset=entry.get('offset'), path_reason=path_reason, archive_path=entry.get('name', '') if 'zip' in schema else '', path_reliability=reliability, integrity=integrity, size=actual_size,
                                     output=target, sha256=entry.get('sha256'), provenance=entry.get('provenance', 'source salvage; original completeness unknown'), status=entry.get('status', 'recovered'), validation=entry.get('validation') or {k: entry[k] for k in ('integrity_check', 'chunks_crc_verified', 'decoded_bytes', 'interlaced') if k in entry}, manifest=str(manifest)))
            except (ValueError, OSError, TypeError) as error:
                errors.append(str(manifest) + ': ' + str(error))
    if spec.tool == 'auto':
        try:
            _auto_rows(root, source_id, stage, diagnostic, manifests)
        except (OSError, ValueError, TypeError, KeyError) as error:
            errors.append(str(root / 'payload') + ': ' + str(error))
    if spec.tool in ('logical_index', 'auto'):
        from revivex_scan_session import ScanSession
        session_path = root / 'payload' / ('session.sqlite' if spec.tool == 'logical_index' else 'logical/session.sqlite')
        if session_path.is_file():
            try:
                _no_symlinks(session_path)
                with ScanSession(session_path) as session:
                    if not manifests:
                        manifests.append(session.summary())
                    for entry in session.iter_candidates():
                        name = entry.get('name') or 'unnamed'
                        relative = str(entry.get('volume_id', 'volume')) + '/' + (entry.get('relative_path') or name).lstrip('/')
                        stage(dict(id=entry['candidate_id'], name=name, relative_path=relative,
                                   path_reliability=entry.get('path_reliability', 'unknown'),
                                   status='logical_candidate', integrity='indexed: validated logical mapping; bytes not yet recovered',
                                   size=entry.get('expected_size', 0), output='',
                                   validation=entry, provenance=entry['provenance'],
                                   session_path=str(session_path), candidate_id=entry['candidate_id']))
                    if hasattr(session, 'iter_directories'):
                        for entry in session.iter_directories():
                            diagnostic({**entry, 'status': 'directory'}, str(session_path))
                    if hasattr(session, 'iter_errors'):
                        for entry in session.iter_errors():
                            diagnostic(entry, str(session_path))
            except (OSError, ValueError, TypeError) as error:
                errors.append(str(session_path) + ': ' + str(error))
    # Stream diagnostic indexes rather than loading potentially millions of candidates.
    for directory in safe_directories:
        index_name = {'carve': 'candidates.jsonl', 'ntfs': 'record_index.jsonl'}.get(spec.tool)
        if not index_name or not (directory / index_name).is_file():
            continue
        index = directory / index_name
        try:
            _no_symlinks(index)
            with index.open(encoding='utf-8') as stream:
                for line in stream:
                    if len(line) > 4 * 1024 * 1024:
                        raise ValueError('Candidate record exceeds 4 MiB')
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        raise ValueError('Candidate must be an object')
                    diagnostic(entry, str(index))
                    for child in entry.get('streams', []):
                        if child.get('status') not in ('recovered', 'skipped_directory_stream'):
                            diagnostic({**entry, **child}, str(index))
        except (OSError, ValueError, TypeError) as error:
            errors.append(str(index) + ': ' + str(error))
    # Files absent from a durable manifest may be interrupted writes. Never mark
    # them verified or eligible for selected export merely because they exist.
    for directory in safe_directories:
        if not directory.exists() or spec.tool == 'auto':
            continue  # auto lists every written file in its own manifests (streamed above)
        for current, dirs, files in os.walk(directory, followlinks=False):
            dirs[:] = [d for d in dirs if not (Path(current) / d).is_symlink()]
            for name in files:
                path = Path(current) / name
                if path.is_symlink() or not path.is_file() or (spec.tool == 'logical_index' and name in ('session.sqlite', 'session.sqlite-wal', 'session.sqlite-shm')) or name in manifest_names or (spec.tool in ('ntfs', 'logical_ntfs') and name in ('record_index.jsonl', 'candidates.jsonl')) or (spec.tool == 'carve' and name == 'candidates.jsonl') or str(path.resolve()) in seen:
                    continue
                relative = path.relative_to(root).as_posix()
                stage(dict(id=hashlib.sha256((source_id + '|' + relative).encode()).hexdigest(), name=name, relative_path=relative,
                                 path_reliability='unconfirmed output path', integrity='unverified: no durable manifest entry',
                                 size=path.stat().st_size, output=str(path.resolve()), status='partial_unverified', validation='', manifest=''))
    if buffer:
        catalog.ingest(source_id, buffer, source.name, str(source))
    if row_count > 1000:
        rows = []
    report = {}
    if (root / 'report.json').is_file():
        try:
            report = _json(root / 'report.json')
        except (ValueError, OSError) as error:
            errors.append(str(error))
    failure_statuses = {'failed', 'incomplete', 'source_changed', 'running', 'scan_limit', 'candidate_limit', 'output_limit'}
    failed_report = report.get('status') == 'failed' or any(m.get('status') in failure_statuses or m.get('scan_status') in ('failed', 'cancelled') or m.get('source_unchanged_stat') is False for m in manifests)
    status = 'cancelled' if cancelled else 'failed' if returncode or errors or failed_report or integrity_failed else 'completed'
    availability = catalog.availability()
    known_failed = catalog.db.execute("SELECT count(*) FROM files WHERE status NOT IN ('directory') AND NOT (" + __import__('revivex_catalog').ELIGIBLE_SQL + ")").fetchone()[0]
    manifest_gaps = any(m.get('status') in ('limited', 'interrupted', 'finished_with_errors') or m.get('errors') or any(v.get('errors') or v.get('scan_status') in ('failed', 'unsupported') for v in m.get('volumes', [])) for m in manifests)
    scan_complete = not manifest_gaps and status == 'completed' and all(m.get('scan_complete', True) and m.get('central_index_complete', True) for m in manifests)
    summary = dict(scan_status='completed_scan' if scan_complete else 'incomplete_scan' if status == 'completed' else status, completeness='known_partial' if known_failed or status != 'completed' or not scan_complete else 'unknown', candidates=availability['candidates'], verified_available=availability['verified_available'], indexed_candidates=catalog.count(status='logical_candidate'), directories=availability['directories'], known_failed=known_failed, original_total=None, original_total_known=False, tool=spec.tool, path_inference_warning=path_inference_warning, source_id=source_id, source_path=spec.source, catalog_path=str(catalog_path), row_count=row_count, rows_truncated=row_count > 1000, returncode=returncode, manifests=manifests, report=report, errors=errors,
                   partial=cancelled or status == 'failed' or unverified_outputs or bool(known_failed) or not scan_complete,
                   warning=(AUTO_WARNING if spec.tool == 'auto' else 'Metadata-only index: selected bytes are read on export. Logical mapping validity does not establish content authenticity, file usability, or completeness. Never execute recovered files.' if spec.tool == 'logical_index' else 'Scan writes staged salvage files. No decryption or original completeness is established. Never execute recovered files. Cancelled jobs retain partial files; only hash-verified manifest entries are eligible for export.'))
    catalog.set_run_summary(summary)
    catalog.close()
    log_path = root / 'worker.log'
    log = ''
    if log_path.exists():
        with log_path.open('rb') as stream:
            stream.seek(max(0, log_path.stat().st_size - 65536))
            log = stream.read().decode('utf-8', errors='replace')
    result = JobResult(status, str(root), rows, summary, log, '; '.join(errors) or (f'Worker exited with code {returncode}' if returncode and not cancelled else ''))
    (root / 'job_result.json').write_text(json.dumps(asdict(result), ensure_ascii=True, indent=2), encoding='utf-8')
    return result


AUTO_WARNING = ('Automatic recovery writes files under their original names when the evidence allows. Grades '
                '(usable / needs review / suspect damaged) are structure checks only; they do not prove original content, '
                'completeness or safety. Never execute recovered files.')
CANCEL_FILE = 'cancel.request'
COOPERATIVE_CANCEL_SECONDS = 30
GRADE_STATUS = {'usable': 'usable', 'needs_review': 'needs_review', 'suspect_damaged': 'suspect_damaged'}


def _jsonl(path, limit=4 * 1024 * 1024):
    with path.open(encoding='utf-8') as stream:
        for line in stream:
            if len(line) > limit:
                raise ValueError(f'{path.name}: record exceeds 4 MiB')
            entry = json.loads(line)
            if not isinstance(entry, dict):
                raise ValueError(f'{path.name}: record must be an object')
            yield entry


def _auto_rows(root, source_id, stage, diagnostic, manifests):
    """Stream an automatic-recovery payload into the catalog, one row at a time."""
    payload = root / 'payload'
    _no_symlinks(payload)
    manifest_path = payload / 'auto_manifest.json'
    if manifest_path.is_file():
        report = _json(manifest_path)
        manifests.append({'path': str(manifest_path), **{k: v for k, v in report.items() if k not in ('source_identity',)}})
    listing, missing = payload / '清单.jsonl', payload / '未恢复清单.jsonl'
    state_db = payload / '_state' / 'extract.sqlite'
    if state_db.is_file():
        # Rebuild the listings from the durable state: a killed worker may not have written them.
        from revivex_named_extract import open_state
        from revivex_organize import write_manifests
        _no_symlinks(state_db)
        extract_state = open_state(state_db)
        try:
            write_manifests(extract_state, payload)
        finally:
            extract_state.close()
    if listing.is_file():
        _no_symlinks(listing)
        for entry in _jsonl(listing):
            output = (payload / entry['output']).absolute()
            _no_symlinks(output)
            if payload not in output.parents:
                raise ValueError('Listed output points outside the workspace')
            try:
                size_ok = output.is_file() and output.stat().st_size == entry.get('size')
            except OSError:
                size_ok = False
            category = entry.get('category_en') or entry.get('grade') or 'needs_review'
            status = 'thumbnail_cache' if category.endswith('thumbnail_cache') else GRADE_STATUS.get(entry.get('grade'), 'needs_review')
            original = str(entry.get('original_path') or '')
            name = original.rsplit('/', 1)[-1] or output.name
            if entry.get('deleted'):  # recovered from a deleted record: kept apart from live files
                status, original = 'deleted_' + status, '_已删除文件/' + original
            stage(dict(id=hashlib.sha256(f"auto|{entry.get('volume')}|{entry.get('record')}".encode('utf-8')).hexdigest(),
                       name=name, relative_path=f"{entry.get('volume')}/{original}",
                       path_reliability='logical_verified' if entry.get('path_known') else 'parent_folder_unknown',
                       integrity=('verified: size matches; SHA-256 recorded when written and re-checked on export' if size_ok
                                  else 'failed: output missing or size differs from the recovery record'),
                       size=entry.get('size') or 0, output=str(output), sha256=entry.get('sha256'), status=status,
                       validation=dict(grade=entry.get('grade'), check=entry.get('check'), category=entry.get('category'),
                                       map_methods=entry.get('map_methods')),
                       provenance=entry.get('origin') or 'rebuilt_block_map', manifest=str(listing)))
    if missing.is_file():
        _no_symlinks(missing)
        for entry in _jsonl(missing):
            original = ('_已删除文件/' if entry.get('deleted') else '') + str(entry.get('original_path') or '')
            # Same identity as a written file: a later resume that writes it replaces this row.
            stage(dict(id=hashlib.sha256(f"auto|{entry.get('volume')}|{entry.get('record')}".encode('utf-8')).hexdigest(),
                       name=original.rsplit('/', 1)[-1] or f"record_{entry.get('record')}",
                       relative_path=f"{entry.get('volume')}/{original}",
                       path_reliability='logical_verified' if entry.get('path_known') else 'parent_folder_unknown',
                       integrity='unavailable: ' + str(entry.get('reason')), size=entry.get('size') or 0, output='',
                       status='not_recovered', validation=dict(reason=entry.get('reason')), manifest=str(missing)))
    state = payload / 'auto.sqlite'
    if state.is_file() and not listing.is_file():
        from revivex_auto import iter_rows
        _no_symlinks(state)
        for entry in iter_rows(state):
            if entry['status'] == 'recovered' and entry['output']:
                output = (payload / entry['output']).absolute()
                _no_symlinks(output)
                try:
                    size_ok = output.is_file() and output.stat().st_size == entry['size']
                except OSError:
                    size_ok = False
                stage(dict(id=hashlib.sha256(f"auto-raw|{entry['kind']}|{entry['offset']}|{entry['sub']}".encode()).hexdigest(),
                           name=entry['name'], relative_path=entry['relative_path'] or entry['name'],
                           path_reliability='name_only', size=entry['size'], output=str(output), sha256=entry['sha256'],
                           integrity=('verified: size matches; SHA-256 recorded when written and re-checked on export'
                                      if size_ok else 'failed: output missing or size differs'),
                           status='recovered', validation=entry['detail'], provenance=f"raw {entry['kind']} candidate at offset {entry['offset']}",
                           manifest=str(state)))
            else:
                diagnostic(dict(entry['detail'], name=entry['name'], offset=entry['offset'], status=entry['status'],
                                format=entry['kind']), str(state))


def _catalog_finished_auto_run(root):
    """An automatic recovery run started outside the app (command line) has listings but no
    catalog yet: build it from the run's own files. Nothing is executed or re-run."""
    request, manifest = root / 'job_request.json', root / 'payload' / 'auto_manifest.json'
    if not (request.is_file() and manifest.is_file()):
        return
    _no_symlinks(request)
    saved = json.loads(request.read_text(encoding='utf-8'))
    if saved.get('tool') != 'auto' or not Path(saved.get('source', '')).is_file():
        return
    collect_results(JobSpec('auto', str(Path(saved['source']).absolute()), str(root), {}), 0)


def reopen_workspace(path):
    """Open only a validated local catalog. Never dispatch saved job requests.

    All paths are anchored to the chosen workspace; serialized catalog/source
    paths are descriptive only and cannot redirect the open operation.
    """
    from revivex_catalog import RecoveryCatalog
    import sqlite3
    root = Path(path).absolute()
    if root.is_file():
        if root.name != 'catalog.sqlite':
            raise ValueError('Choose a recovery workspace or its catalog.sqlite')
        root = root.parent
    _no_symlinks(root)
    db_path = root / 'catalog.sqlite'
    _no_symlinks(db_path)
    if not db_path.is_file():
        _catalog_finished_auto_run(root)
    if not db_path.is_file():
        raise ValueError('Workspace has no recovery catalog')
    with sqlite3.connect(db_path.as_uri()+'?mode=ro', uri=True) as check:
        check.execute('PRAGMA trusted_schema=OFF')
        if check.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
            raise ValueError('Recovery catalog is corrupt')
        required = {'id','source_id','name','relative_path','folder','type_group','output','size','path_reliability','integrity','status','validation','provenance','expected_sha256','selected'}
        columns = {row[1] for row in check.execute('PRAGMA table_info(files)')}
        if not required <= columns or check.execute("SELECT count(*) FROM sqlite_master WHERE type IN ('trigger','view')").fetchone()[0]:
            raise ValueError('Unsupported recovery catalog schema')
        for (payload,) in check.execute("SELECT provenance FROM files WHERE status='logical_candidate'"):
            metadata = json.loads(payload)
            session_path = Path(metadata.get('session_path', '')).absolute()
            _no_symlinks(session_path)
            if root not in session_path.parents or not session_path.is_file():
                raise ValueError('Indexed session points outside the chosen workspace or is missing')
        for (output,) in check.execute("SELECT output FROM files WHERE output<>''"):
            target = Path(output).absolute()
            _no_symlinks(target)
            if root not in target.parents:
                raise ValueError('Staged output points outside the chosen workspace')
    return RecoveryCatalog(db_path)


class JobRunner:
    """One isolated child at a time; poll never performs I/O or hashes files."""
    def __init__(self):
        self._process = None
        self._thread = None
        self._result = None
        self._cancelled = False
        self._lock = threading.Lock()

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self, spec):
        if self.running:
            raise RuntimeError('A job is already running')
        spec = validate_spec(spec)
        root = Path(spec.output)
        if spec.tool == 'auto' and spec.options.get('resume') is True:
            # Continue in place: keep the original request, add a new one for this run.
            config = root / f'job_request.resume-{int(time.time() * 1000)}.json'
            for stale in ('job_result.json', 'progress.json', CANCEL_FILE):
                if (root / stale).is_file():
                    os.replace(root / stale, root / (stale + '.previous'))
        else:
            root.mkdir(parents=True, exist_ok=False)
            config = root / 'job_request.json'
        with config.open('x', encoding='utf-8') as handle:
            handle.write(json.dumps(asdict(spec), ensure_ascii=True))
        self._result, self._cancelled, self._spec = None, False, spec
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if os.name == 'nt' else 0
        try:
            self._process = subprocess.Popen(worker_command(config), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL, creationflags=flags)
        except OSError as error:
            self._result = JobResult('failed', str(root), error=str(error))
            return
        self._thread = threading.Thread(target=self._monitor, args=(spec,), daemon=True)
        self._thread.start()

    def _monitor(self, spec):
        code = self._process.wait()
        try:
            result = collect_results(spec, code, self._cancelled)
        except Exception as error:
            result = JobResult('cancelled' if self._cancelled else 'failed', spec.output,
                               summary={'partial': True}, error=f'Output reconciliation failed: {error}')
        with self._lock:
            self._result = result

    def poll(self):
        with self._lock:
            return self._result

    def cancel(self, grace=COOPERATIVE_CANCEL_SECONDS):
        """Automatic recovery stops at its next safe point (summary and listings are written);
        it is killed only if it has not stopped after ``grace`` seconds. Other tools are killed."""
        if self._process is None or self._process.poll() is not None:
            return
        self._cancelled = True
        process = self._process
        spec = getattr(self, '_spec', None)
        if spec is not None and spec.tool == 'auto' and grace > 0:
            try:
                (Path(spec.output) / CANCEL_FILE).write_text('cancel requested\n', encoding='utf-8')
            except OSError:
                grace = 0
            else:
                def later():
                    try:
                        process.wait(timeout=grace)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                threading.Thread(target=later, daemon=True).start()
                return
        try:
            process.kill()
        except ProcessLookupError:
            pass


def self_test(timeout=30):
    """Exercise real (including frozen) worker, catalog and selected export.

    Uses only synthetic data in a private temporary directory and never runs a
    recovered payload. Raises RuntimeError on failure so packaging can fail shut.
    """
    import tempfile
    import time
    import zipfile
    from revivex_catalog import RecoveryCatalog
    if timeout <= 0:
        raise ValueError('Self-test timeout must be positive')
    for module in MODULES.values():
        importlib.import_module(module)
    runner = JobRunner()
    with tempfile.TemporaryDirectory(prefix='revivex-self-test-') as temporary:
        root = Path(temporary)
        source = root / 'synthetic.zip'
        payload = b'ReViveX synthetic frozen-worker integrity test.\n'
        with zipfile.ZipFile(source, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('sample-folder/example.txt', payload)
        original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        deadline = time.monotonic() + timeout
        try:
            runner.start(JobSpec('zip', str(source), str(root / 'scan')))
            while runner.poll() is None:
                if time.monotonic() >= deadline:
                    raise RuntimeError('Isolated recovery worker self-test timed out')
                time.sleep(.02)
            result = runner.poll()
            if result.status != 'completed':
                raise RuntimeError(f'Isolated recovery worker failed: {result.error}; {result.log[-2000:]}')
            with RecoveryCatalog(result.summary['catalog_path']) as catalog:
                if catalog.count() != 1:
                    raise RuntimeError('Worker catalog did not contain exactly one synthetic file')
                row = catalog.query(limit=1)[0]
                if not row['integrity'].startswith('verified:') or row['relative_path'] != 'sample-folder/example.txt':
                    raise RuntimeError('Worker output integrity or archive path was not preserved')
                catalog.select_filtered()
                exported = catalog.export_selected(root / 'selected-export')
            if exported['recovered'] != 1 or exported['failed'] or exported['cancelled']:
                raise RuntimeError('Synthetic selected export failed')
            records = [json.loads(line) for line in Path(exported['report']).read_text(encoding='utf-8').splitlines()]
            files = [entry for entry in records if entry.get('record') == 'file']
            if len(files) != 1 or files[0].get('export_status') != 'copied-and-verified':
                raise RuntimeError('Selected export verification report is incomplete')
            recovered = root / 'selected-export' / files[0]['output']
            if recovered.read_bytes() != payload:
                raise RuntimeError('Selected output differs from synthetic input')
            if hashlib.sha256(source.read_bytes()).hexdigest() != original_hash:
                raise RuntimeError('Synthetic source changed during scan')
            if time.monotonic() >= deadline:
                raise RuntimeError('Recovery lifecycle self-test exceeded timeout')
            return {'status': 'passed', 'engine_imports': len(MODULES), 'isolated_worker': True,
                    'frozen': bool(getattr(sys, 'frozen', False)), 'catalog_files': 1,
                    'selected_export_verified': True, 'source_unchanged': True}
        finally:
            runner.cancel()
            if runner._process is not None:
                try:
                    runner._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    runner._process.kill()
                    runner._process.wait(timeout=5)
            if runner._thread is not None:
                runner._thread.join(timeout=5)
            # Export manifests intentionally read-only; clear that attribute
            # only within our own private temp tree for Windows cleanup.
            for path in root.rglob('*'):
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o600)


if __name__ == '__main__':
    if not dispatch_worker():
        raise SystemExit('This module is an internal job worker; start the desktop app.')
