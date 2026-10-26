"""Shared stage plumbing for long recovery runs: progress, cancel, durable files.

Every long stage reports through ``StageContext.progress()``, which rewrites
``progress.json`` atomically about twice a second. The desktop UI reads that
file (see ``MainWindow.render_auto_progress``); field names are a contract:

  stage, stage_index, stage_count, status, unit ('bytes' or 'items'),
  scanned_bytes (done), planned_bytes (total or null), bytes_per_second,
  verified_files, candidates, failed, extra_read_bytes, message.

Cancellation is cooperative (``ctx.check_cancel()`` between bounded steps) and
also survives a hard kill: each stage keeps its own durable checkpoint.
"""
from __future__ import annotations

from collections import deque
import json
import os
from pathlib import Path
import time


class Cancelled(Exception):
    """Raised at a safe point when the user cancelled; durable state is kept."""


class StopRun(Exception):
    """Stop the run for a reportable reason (space low, source changed...)."""

    def __init__(self, status, reason):
        super().__init__(reason)
        self.status, self.reason = status, reason


def replace_with_retry(temporary, target, attempts=240, delay=0.5):
    """os.replace that waits while Windows readers hold the target open."""
    for attempt in range(attempts):
        try:
            os.replace(temporary, target)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)


def write_json_atomic(path, value, *, durable=True, retries=240):
    path = Path(path)
    temporary = path.with_name(path.name + '.tmp')
    with open(temporary, 'w', encoding='utf-8') as handle:
        json.dump(value, handle, ensure_ascii=False, indent=1, default=str)
        handle.flush()
        if durable:
            os.fsync(handle.fileno())
    replace_with_retry(temporary, path, attempts=retries)


def read_json(path, default=None, limit=64 * 1024 * 1024):
    path = Path(path)
    try:
        if path.stat().st_size > limit:
            raise ValueError(f'{path.name} exceeds size limit')
        return json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return default


def place_exclusive(temporary, target):
    """Move a finished temp file to ``target`` without ever replacing a file.

    Raises FileExistsError when the target exists. POSIX ``rename`` would
    silently replace, so a hard link is used there (atomic, fails if present).
    """
    temporary, target = str(temporary), str(target)
    if os.name == 'nt':
        os.rename(temporary, target)  # Windows rename refuses existing targets.
        return
    try:
        os.link(temporary, target)
    except FileExistsError:
        raise
    except OSError:
        # File systems without hard links (FAT/exFAT): check, then rename.
        if os.path.lexists(target):
            raise FileExistsError(target)
        os.rename(temporary, target)
        return
    os.unlink(temporary)


def move_exclusive(source, target):
    """Rename ``source`` to ``target`` (same volume) without replacing anything."""
    place_exclusive(source, target)


class StageContext:
    """Progress/cancel hub shared by all stages of one run."""

    def __init__(self, progress_path=None, cancel=None, log=None, interval=0.5):
        self.progress_path = Path(progress_path) if progress_path else None
        self.cancel = cancel or (lambda: False)
        self.log_function = log
        self.interval = interval
        self.stage, self.stage_index, self.stage_count = 'prepare', 0, None
        self.status, self.message, self.unit = 'running', '', 'bytes'
        self.done, self.total = 0, None
        self.counts = dict(verified_files=0, candidates=0, failed=0)
        self.extra_read_bytes = 0
        self._last = 0.0
        self._samples = deque(maxlen=20)
        self.started = time.monotonic()
        self.history = []

    # --- stage bookkeeping ---------------------------------------------
    def begin(self, stage, index, count=None, *, unit='bytes', total=None, done=0, message=''):
        self.stage, self.stage_index = stage, index
        if count is not None:
            self.stage_count = count
        self.unit, self.total, self.done, self.message = unit, total, done, message
        self._samples.clear()
        self.history.append(dict(stage=stage, started=time.time()))
        self.log(f'stage {index}: {stage}')
        self.progress(force=True)
        self.check_cancel()  # every stage boundary is a safe cancel point

    def advance(self, done=None, *, add=0, total=None, message=None, **counts):
        if done is not None:
            self.done = done
        self.done += add
        if total is not None:
            self.total = total
        if message is not None:
            self.message = message
        for key, value in counts.items():
            self.counts[key] = value
        self.progress()

    def check_cancel(self):
        if self.cancel():
            raise Cancelled('Cancelled by user; durable progress is kept for resume')

    def log(self, text):
        if self.log_function:
            self.log_function(text)

    # --- progress.json -------------------------------------------------
    def snapshot(self):
        now = time.monotonic()
        speed = None
        if self.unit == 'bytes' and len(self._samples) >= 2:
            (t0, b0), (t1, b1) = self._samples[0], self._samples[-1]
            if t1 - t0 >= 5 and b1 - b0 >= 64 * 1024 * 1024:
                speed = (b1 - b0) / (t1 - t0)
        return dict(schema='revivex.auto-recovery.progress', stage=self.stage, stage_index=self.stage_index,
                    stage_count=self.stage_count, status=self.status, unit=self.unit,
                    scanned_bytes=self.done, planned_bytes=self.total, bytes_per_second=speed,
                    verified_files=self.counts.get('verified_files', 0), candidates=self.counts.get('candidates', 0),
                    failed=self.counts.get('failed', 0), extra_read_bytes=self.extra_read_bytes,
                    message=self.message, elapsed_seconds=round(now - self.started, 3), updated_at=time.time())

    def progress(self, force=False):
        now = time.monotonic()
        if not force and now - self._last < self.interval:
            return
        self._last = now
        self._samples.append((now, self.done))
        if self.progress_path is None:
            return
        try:
            # Not fsynced: progress is advisory and rewritten constantly.
            write_json_atomic(self.progress_path, self.snapshot(), durable=False, retries=4)
        except OSError:
            pass  # A reader holds the file (Windows); the next tick retries.
