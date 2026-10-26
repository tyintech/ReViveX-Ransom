"""Rebuild-the-block-map recovery route (VHDX mapping lost, guest NTFS plaintext).

Stages (each resumable, cancellable, reporting to progress.json):
  evidence_scan -> evidence_index -> block_map -> volume_membership ->
  block_match -> named_extract -> grading -> organize

Intermediate files (evidence, SQLite indexes, block map) live in the work
folder, which may be a fast temporary disk; recovered files are written to the
output folder. The source is opened read-only and read with bounded reads.
Stage completion is recorded in <work>/pipeline.json only after a stage's own
durable state is complete, so an interruption repeats at most one stage's tail.
"""
from __future__ import annotations

from pathlib import Path
import time

from revivex_block_map import Rebuilder, load_maps, map_finished
from revivex_block_match import BlockMatcher
from revivex_evidence import EvidenceScan, MagicIndex, build_index, open_index, zero_mibs
from revivex_named_extract import NamedExtractor, grade_extracted, open_state
from revivex_organize import organize, write_manifests
from revivex_stage import read_json, write_json_atomic
from revivex_volume_model import build_models

MiB = 1024 * 1024
STAGES = ('evidence_scan', 'evidence_index', 'block_map', 'volume_membership', 'block_match', 'named_extract',
          'grading', 'organize')


class RebuildRecovery:
    def __init__(self, source, output, work, *, damaged=(), options=None, ctx, first_index=3, stage_count=11):
        self.source, self.output, self.work = source, Path(output), Path(work)
        self.damaged = [tuple(r) for r in damaged]
        self.options = dict(options or {})
        self.ctx, self.first_index, self.stage_count = ctx, first_index, stage_count
        self.pipeline_path = self.work / 'pipeline.json'

    def _pipeline(self):
        return read_json(self.pipeline_path, {}) or {}

    def _done(self, stage, result):
        pipeline = self._pipeline()
        pipeline.setdefault('stages', {})[stage] = dict(status='finished', finished_at=time.time(), result=result)
        write_json_atomic(self.pipeline_path, pipeline)

    def _begin(self, stage, **kwargs):
        self.ctx.begin(stage, self.first_index + STAGES.index(stage), self.stage_count, **kwargs)

    def run(self):
        self.work.mkdir(parents=True, exist_ok=True)
        self.output.mkdir(parents=True, exist_ok=True)
        pipeline = self._pipeline()
        finished = {k for k, v in pipeline.get('stages', {}).items() if v.get('status') == 'finished'}
        results = {k: v.get('result') for k, v in pipeline.get('stages', {}).items()}
        evidence, index_path, map_path = self.work / 'evidence', self.work / 'index.sqlite', self.work / 'map.sqlite'
        state_dir = self.output / '_state'
        state_dir.mkdir(parents=True, exist_ok=True)

        if 'evidence_scan' not in finished:
            self._begin('evidence_scan', unit='bytes')
            scan = EvidenceScan(self.source, evidence, damaged=self.damaged, ctx=self.ctx,
                                checkpoint_seconds=self.options.get('checkpoint_seconds', 30.0),
                                reserve_bytes=self.options.get('reserve_bytes', 1024 * MiB),
                                limit_bytes=self.options.get('evidence_limit_bytes'))
            checkpoint = scan.run()
            results['evidence_scan'] = dict(status=checkpoint['status'], scanned=checkpoint['scanned'],
                                            counts=checkpoint['counts'], ranges=checkpoint['ranges'],
                                            seconds=round(checkpoint['elapsed'], 1),
                                            unreadable_ranges=checkpoint.get('unread', []))
            self._done('evidence_scan', results['evidence_scan'])
        if 'evidence_index' not in finished:
            self._begin('evidence_index', unit='bytes')
            results['evidence_index'] = build_index(evidence, index_path, ctx=self.ctx)
            self._done('evidence_index', results['evidence_index'])

        index = open_index(index_path, readonly=True)
        magic = MagicIndex(evidence)
        zeros = zero_mibs(evidence)
        try:
            if 'block_map' not in finished or not map_finished(map_path):
                self._begin('block_map', unit='items')
                stage_hook = lambda: self._begin('volume_membership', unit='items')
                rebuilder = Rebuilder(index, magic, zeros=zeros, source_size=len(self.source), damaged=self.damaged,
                                      options=self.options, ctx=self.ctx)
                rebuilder.membership_hook = stage_hook
                rebuilder.run()
                rebuilder.save(map_path)
                report = rebuilder.report
                results['block_map'] = _map_summary(rebuilder)
                self._done('block_map', results['block_map'])
                results['volume_membership'] = dict(report.get('membership', {}), volume_status=report.get('volume_status'),
                                                    embedded_in=report.get('embedded_in'))
                self._done('volume_membership', results['volume_membership'])
            maps, membership, report = load_maps(map_path)
            if not maps:
                raise ValueError('No guest NTFS volume could be reconstructed from the evidence')
            if 'volume_membership' not in self._finished():
                self._begin('volume_membership', unit='items')
                self._done('volume_membership', results.get('volume_membership') or {})
            models = build_models(index, maps, membership, report)

            if 'block_match' not in finished:
                self._begin('block_match', unit='items')
                if self.options.get('match_missing_blocks', True):
                    matcher = BlockMatcher(self.source, models, magic, zeros=zeros, damaged=self.damaged,
                                           state_path=self.work / 'match.sqlite', options=self.options.get('match'),
                                           ctx=self.ctx)
                    results['block_match'] = matcher.run()
                    results['block_match']['applied'] = matcher.apply(map_path)
                    matcher.state.close()
                else:
                    results['block_match'] = dict(skipped='disabled by option')
                self._done('block_match', results['block_match'])
                models = matcher = None  # release the first models before building the second set
                maps, membership, report = load_maps(map_path)
                models = build_models(index, maps, membership, report)
        finally:
            index.close()

        state = open_state(state_dir / 'extract.sqlite')
        try:
            if 'named_extract' not in finished:
                self._begin('named_extract', unit='items')
                extractor = NamedExtractor(self.source, models, evidence, self.output, state, damaged=self.damaged,
                                           ctx=self.ctx, reserve_bytes=self.options.get('reserve_bytes', 1024 * MiB),
                                           include_deleted=self.options.get('include_deleted', True))
                results['named_extract'] = extractor.run()
                self._done('named_extract', results['named_extract'])
            if 'grading' not in finished:
                self._begin('grading', unit='items')
                results['grading'] = grade_extracted(state, self.output, ctx=self.ctx)
                self._done('grading', results['grading'])
            if 'organize' not in finished:
                self._begin('organize', unit='items')
                results['organize'] = organize(state, self.output, ctx=self.ctx)
                self._done('organize', results['organize'])
            results['manifests'] = write_manifests(state, self.output)
            results['totals'] = totals(state)
        finally:
            state.close()
        results['volumes'] = [dict(volume=v.volume, label=v.label, cluster_size=v.cluster_size, block_size=v.block_size,
                                   partition_shift=v.shift, mapped_blocks=len(v.blocks), unresolved_blocks=len(v.unresolved))
                              for v in maps.values()]
        results['work_dir'] = str(self.work)
        return results

    def _finished(self):
        return {k for k, v in self._pipeline().get('stages', {}).items() if v.get('status') == 'finished'}


def _map_summary(rebuilder):
    from collections import Counter
    out = dict(cluster=rebuilder.report.get('cluster', {}).get('chosen'), volumes=[])
    for vmap, anchors, _ in rebuilder.maps:
        out['volumes'].append(dict(volume=vmap.volume, label=vmap.label, status=rebuilder.status[vmap.volume],
                                   block_size=vmap.block_size, partition_shift=vmap.shift, residue=vmap.residue,
                                   anchors=len(anchors), methods=dict(Counter(e[1] for e in vmap.blocks.values())),
                                   unresolved=len(vmap.unresolved)))
    out['interpolation'] = rebuilder.report.get('interpolation')
    out['geometry'] = [v.get('fit') for v in rebuilder.report.get('volumes', [])]
    return out


def totals(state):
    rows = state.execute("SELECT status, grade, deleted, count(*), coalesce(sum(size),0) FROM files "
                         "GROUP BY status, grade, deleted").fetchall()
    result = dict(extracted=0, extracted_bytes=0, not_extracted=0, by_grade={},
                  deleted=dict(extracted=0, not_extracted=0, by_grade={}))
    for status, grade, deleted, count, size in rows:
        bucket = result['deleted'] if deleted else result
        if status == 'extracted':
            bucket['extracted'] += count
            bucket['by_grade'][grade or 'pending'] = bucket['by_grade'].get(grade or 'pending', 0) + count
            if not deleted:
                result['extracted_bytes'] += size
        else:
            bucket['not_extracted'] += count
    reasons = state.execute("SELECT substr(reason, 1, instr(reason || ':', ':') - 1) AS r, count(*) FROM files "
                            "WHERE status<>'extracted' GROUP BY r ORDER BY 2 DESC LIMIT 20").fetchall()
    result['not_extracted_reasons'] = dict(reasons)
    return result
