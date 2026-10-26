"""Sort recovered files into 最终结果/可用|待确认|疑似损坏|缩略图缓存 by moving only.

Nothing is deleted or overwritten. Every move is first recorded in the state
database (intent), then performed with an exclusive rename, then marked done,
so an interruption at any point is completed or undone correctly on resume.
A readable log is appended to 最终结果/_整理记录.tsv. ``undo()`` moves every
file back to where extraction put it and logs that to _撤回记录.tsv.
Thumbs.db caches go to their own folder (field lesson 9) so result folders
are not cluttered by thumbnail databases.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from revivex_grading import SUSPECT, REVIEW, USABLE, is_thumbnail_cache
from revivex_named_extract import DELETED, STAGING, long_path
from revivex_stage import move_exclusive, replace_with_retry

FINAL = '最终结果'
DELETED_FOLDER = '已删除文件'
CATEGORY = {USABLE: '可用', REVIEW: '待确认', SUSPECT: '疑似损坏'}
THUMBNAILS = '缩略图缓存'
CATEGORY_ENGLISH = {'可用': 'usable', '待确认': 'needs_review', '疑似损坏': 'suspect_damaged', '缩略图缓存': 'thumbnail_cache'}


def category_for(name, grade):
    return THUMBNAILS if is_thumbnail_cache(name) else CATEGORY.get(grade, CATEGORY[REVIEW])


def _free_target(root, relative, number):
    candidate = relative
    for attempt in range(1000):
        path = root / candidate
        parent = path.parent
        while os.path.lexists(long_path(parent)) and not os.path.isdir(long_path(parent)):
            parent = parent.with_name(parent.name + '__dir')
        path = parent / path.name
        if not os.path.lexists(long_path(path)):
            return path
        stem, dot, suffix = Path(candidate).name.rpartition('.')
        tag = f'__r{number}' + (f'-{attempt}' if attempt else '')
        name = f'{stem}.{tag}.{suffix}' if dot and stem else f'{Path(candidate).name}.{tag}'
        candidate = str(Path(candidate).with_name(name))
    raise FileExistsError(relative)


def _same_file(a, b):
    try:
        return os.path.samefile(long_path(a), long_path(b))
    except OSError:
        return False


def _matches(path, size, digest):
    from revivex_named_extract import sha256_file
    try:
        return os.path.getsize(long_path(path)) == size and sha256_file(long_path(path)) == digest
    except OSError:
        return False


def _reconcile_pending(state, root):
    """Finish or abandon moves whose intent was recorded before an interruption."""
    pending = state.execute('SELECT m.id, m.volume, m.number, m.src, m.dst, f.size, f.sha256 FROM moves m '
                            'JOIN files f ON f.volume=m.volume AND f.number=m.number WHERE m.done=0 AND m.undone=0').fetchall()
    for move_id, vid, number, src, dst, size, digest in pending:
        source, target = root / src, root / dst
        has_source, has_target = os.path.lexists(long_path(source)), os.path.lexists(long_path(target))
        if has_source and has_target and _same_file(source, target):
            os.unlink(long_path(source))  # killed between link and unlink: the move itself is complete
            has_source = False
        if has_source and not has_target:
            try:
                os.makedirs(long_path(target.parent), exist_ok=True)
                move_exclusive(long_path(source), long_path(target))
                has_source, has_target = False, True
            except OSError:
                continue  # retried on the next run; the file stays listed at its staging path
        if not has_source and has_target and _matches(target, size, digest):
            with state:
                state.execute('UPDATE moves SET done=1 WHERE id=?', (move_id,))
                state.execute('UPDATE files SET final=? WHERE volume=? AND number=?', (dst, vid, number))
        elif has_source:
            with state:  # target taken by something else: abandon this intent and plan the move again
                state.execute('UPDATE moves SET undone=1 WHERE id=?', (move_id,))


def organize(state, root, ctx=None, batch=500):
    root = Path(root)
    final_root = root / FINAL
    final_root.mkdir(parents=True, exist_ok=True)
    log = open(final_root / '_整理记录.tsv', 'a', encoding='utf-8')
    try:
        _reconcile_pending(state, root)
        rows = state.execute("SELECT volume, number, label, staged, grade FROM files WHERE status='extracted' "
                             "AND final IS NULL AND grade IS NOT NULL").fetchall()
        counts = {}
        for start in range(0, len(rows), batch):
            if ctx:
                ctx.check_cancel()
                ctx.advance(start, total=len(rows))
            planned = []
            for vid, number, label, staged, grade in rows[start:start + batch]:
                source = root / STAGING / staged
                if not os.path.lexists(long_path(source)):
                    counts['missing_in_staging'] = counts.get('missing_in_staging', 0) + 1
                    continue
                category = category_for(Path(staged).name, grade)
                if staged.startswith(DELETED + '/'):  # deleted files: 最终结果/已删除文件/<category>/<volume>/<path>
                    category, rest = f'{DELETED_FOLDER}/{category}', staged[len(DELETED) + 1:]
                else:
                    rest = staged
                try:
                    target = _free_target(final_root, f'{category}/{rest}', number)
                except OSError:
                    counts['move_errors'] = counts.get('move_errors', 0) + 1
                    continue
                planned.append([vid, number, label, category, source, target])
            # 1. Intents are durable before any file moves (one transaction per batch).
            with state:
                for item in planned:
                    src, dst = item[4].relative_to(root).as_posix(), item[5].relative_to(root).as_posix()
                    item.append(state.execute('INSERT INTO moves(volume, number, src, dst) VALUES(?,?,?,?)',
                                              (item[0], item[1], src, dst)).lastrowid)
            # 2. Exclusive renames; one locked or odd file never stops the stage.
            done = []
            for vid, number, label, category, source, target, move_id in planned:
                try:
                    os.makedirs(long_path(target.parent), exist_ok=True)
                    try:
                        move_exclusive(long_path(source), long_path(target))
                    except FileExistsError:
                        target = _free_target(final_root, target.relative_to(final_root).as_posix(), number)
                        with state:  # the intent must name the real destination before the move
                            state.execute('UPDATE moves SET dst=? WHERE id=?', (target.relative_to(root).as_posix(), move_id))
                        os.makedirs(long_path(target.parent), exist_ok=True)
                        move_exclusive(long_path(source), long_path(target))
                except OSError:
                    counts['move_errors'] = counts.get('move_errors', 0) + 1
                    continue  # intent stays pending; reconciled or retried on the next run
                done.append((move_id, vid, number, source.relative_to(root).as_posix(), target.relative_to(root).as_posix(), label, category))
            # 3. Completion marks (a crash before this is reconciled on resume).
            with state:
                for move_id, vid, number, src, dst, label, category in done:
                    state.execute('UPDATE moves SET done=1, dst=? WHERE id=?', (dst, move_id))
                    state.execute('UPDATE files SET final=? WHERE volume=? AND number=?', (dst, vid, number))
            for move_id, vid, number, src, dst, label, category in done:
                log.write(f'{label}\t{number}\t{src}\t{dst}\n')
                counts[category] = counts.get(category, 0) + 1
        log.flush()
        _remove_empty_dirs(root / STAGING)
        if ctx:
            ctx.advance(len(rows), total=len(rows))
        moved = sum(v for k, v in counts.items() if k not in ('missing_in_staging', 'move_errors'))
        return dict(moved_now=moved, by_category=counts)
    finally:
        log.close()


def undo(state, root):
    """Move organized files back into the extraction folder (reverse order)."""
    root = Path(root)
    log_path = root / FINAL / '_撤回记录.tsv'
    log_path.parent.mkdir(parents=True, exist_ok=True)
    restored = skipped = 0
    with open(log_path, 'a', encoding='utf-8') as log:
        for move_id, vid, number, src, dst in state.execute('SELECT id, volume, number, src, dst FROM moves WHERE done=1 AND undone=0 ORDER BY id DESC').fetchall():
            source, target = root / src, root / dst
            has_source, has_target = os.path.lexists(long_path(source)), os.path.lexists(long_path(target))
            if has_source and has_target and _same_file(source, target):
                os.unlink(long_path(target))  # an earlier undo was killed between link and unlink
                has_target = False
            if has_target and not has_source:
                try:
                    os.makedirs(long_path(source.parent), exist_ok=True)
                    move_exclusive(long_path(target), long_path(source))
                except OSError:
                    skipped += 1
                    continue
                has_source = True
            elif not (has_source and not has_target):
                skipped += 1
                continue
            # Either moved back now, or an earlier undo moved it back before recording it.
            with state:
                state.execute('UPDATE moves SET undone=1 WHERE id=?', (move_id,))
                state.execute('UPDATE files SET final=NULL WHERE volume=? AND number=?', (vid, number))
            log.write(f'{number}\t{dst}\t{src}\n')
            restored += 1
    return dict(restored=restored, skipped=skipped)


def _remove_empty_dirs(base):
    """Only folders this program created and emptied by moving; files are never removed."""
    base = long_path(base)
    if not os.path.isdir(base):
        return
    for current, dirs, files in os.walk(base, topdown=False):
        if not dirs and not files and current != base:
            try:
                os.rmdir(current)
            except OSError:
                pass


def write_manifests(state, root):
    """Stream 清单.jsonl (written files) and 未恢复清单.jsonl (not written, with reasons)."""
    root = Path(root)
    counts = dict(files=0, not_recovered=0)
    with open(root / '清单.jsonl.tmp', 'w', encoding='utf-8') as listing, \
            open(root / '未恢复清单.jsonl.tmp', 'w', encoding='utf-8') as missing:
        for row in state.execute('SELECT volume, number, label, status, reason, path, path_known, staged, final, size, '
                                 'sha256, grade, detail, methods, origin, deleted FROM files ORDER BY volume, path'):
            vid, number, label, status, reason, path, known, staged, final, size, digest, grade, detail, methods, origin, deleted = row
            if status == 'extracted':
                output = final or f'{STAGING}/{staged}'
                category = english = None
                if final:
                    parts = Path(final).parts
                    category = '/'.join(parts[1:3]) if parts[1] == DELETED_FOLDER else parts[1]
                    english = CATEGORY_ENGLISH.get(parts[2] if parts[1] == DELETED_FOLDER else parts[1])
                    if deleted and english:
                        english = 'deleted_' + english
                listing.write(json.dumps(dict(volume=label, record=number, original_path=path, path_known=bool(known),
                                              output=output, category=category, deleted=bool(deleted),
                                              category_en=english, size=size, sha256=digest,
                                              grade=grade, check=detail, map_methods=(methods or '').split(','),
                                              origin=origin), ensure_ascii=False) + '\n')
                counts['files'] += 1
            else:
                missing.write(json.dumps(dict(volume=label, record=number, original_path=path, path_known=bool(known),
                                              size=size, reason=reason, deleted=bool(deleted)), ensure_ascii=False) + '\n')
                counts['not_recovered'] += 1
        listing.flush()
        os.fsync(listing.fileno())
        missing.flush()
        os.fsync(missing.fileno())
    replace_with_retry(root / '清单.jsonl.tmp', root / '清单.jsonl')
    replace_with_retry(root / '未恢复清单.jsonl.tmp', root / '未恢复清单.jsonl')
    return counts


def main(argv=None):
    """Command line: undo or redo the sorting of one automatic-recovery output folder."""
    import argparse
    from revivex_named_extract import open_state
    parser = argparse.ArgumentParser(description='Undo (or redo) the move-only sorting into 最终结果/.')
    parser.add_argument('output', type=Path, help='The automatic-recovery output folder (the one holding 最终结果)')
    parser.add_argument('--undo', action='store_true', help='Move every sorted file back to where extraction wrote it')
    args = parser.parse_args(argv)
    state_path = args.output / '_state' / 'extract.sqlite'
    if not state_path.is_file():
        raise SystemExit('No recovery state found in that folder')
    state = open_state(state_path)
    try:
        result = undo(state, args.output) if args.undo else organize(state, args.output)
        write_manifests(state, args.output)
    finally:
        state.close()
    print(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
