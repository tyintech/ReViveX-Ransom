"""Workspace reopening, unavailable records and recursive folder/export regressions."""
import hashlib
import json
from pathlib import Path
import sqlite3
import pytest
from revivex_catalog import RecoveryCatalog
from revivex_jobs import JobSpec, build_arguments, collect_results, reopen_workspace


def row(root, path, payload=b'fixture', **extra):
    target = root / 'payload' / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return dict(name=Path(path).name, relative_path=path, output=str(target), size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(), integrity='verified: size and SHA-256',
                status='recovered', path_reliability='logical_verified', **extra)


def test_deep_unicode_same_names_empty_dirs_and_recursive_selection(tmp_path):
    with RecoveryCatalog(tmp_path/'catalog.sqlite') as catalog:
        paths = ['卷/一/二/三/四/五/同名.txt', '卷/一/二/三/四/五/子/同名.txt', '卷/另一/同名.txt']
        rows = [row(tmp_path,p) for p in paths]
        rows.append(dict(name='空',relative_path='卷/一/二/三/四/五/空',status='directory',integrity='verified: directory metadata only',path_reliability='logical_verified'))
        rows.append(dict(name='lost.txt',relative_path='卷/一/lost.txt',status='corrupt',integrity='unavailable: missing runs',path_reliability='logical_verified'))
        catalog.ingest('source',rows)
        catalog.select_folder('source','卷/一')
        assert catalog.selected_count()==3
        assert catalog.count()==5
        assert catalog.count(eligible_only=True)==4
        assert catalog.folders('source',parent='卷/一/二/三/四/五') == [dict(source_id='source',path='卷/一/二/三/四/五/子',count=1),dict(source_id='source',path='卷/一/二/三/四/五/空',count=1)]
        result = catalog.export_selected(tmp_path/'export')
        assert result['recovered']==2 and result['directories_created']==1
        roots = [p for p in (tmp_path/'export').iterdir() if p.is_dir()]
        assert len(roots)==1
        for p in paths[:2]:
            assert (roots[0]/p).read_bytes()==b'fixture'
        assert (roots[0]/'卷/一/二/三/四/五/空').is_dir()
        assert not (roots[0]/paths[2]).exists()


def test_reopen_persists_summary_selection_and_pages_without_execution(tmp_path):
    with RecoveryCatalog(tmp_path/'catalog.sqlite') as catalog:
        catalog.ingest('source',(row(tmp_path,f'folder/{n}.txt') for n in range(405)))
        catalog.set_run_summary({'known_failed':3,'original_total':None,'completeness':'known_partial'})
        catalog.select_filtered(search='folder/')
    (tmp_path/'job_request.json').write_text(json.dumps({'tool':'arbitrary_shell','command':'must never run'}))
    with reopen_workspace(tmp_path) as reopened:
        assert reopened.count()==405 and reopened.selected_count()==405
        assert len(reopened.query(limit=200,offset=200))==200
        assert reopened.run_summary()['known_failed']==3
        reopened.select_filtered(False,search='/4')
        assert reopened.selected_count()<405
        result = reopened.export_selected(tmp_path/'export')
        assert result['scan_summary']['known_failed']==3


def test_reopen_rejects_external_staging_and_triggers(tmp_path):
    workspace = tmp_path/'work'; workspace.mkdir()
    with RecoveryCatalog(workspace/'catalog.sqlite') as catalog:
        catalog.ingest('source',[row(tmp_path,'external.txt')])
    with pytest.raises(ValueError,match='outside'):
        reopen_workspace(workspace)
    with sqlite3.connect(workspace/'catalog.sqlite') as db:
        db.execute("UPDATE files SET output=''")
        db.execute('CREATE TRIGGER hostile AFTER UPDATE ON files BEGIN DELETE FROM files; END')
    with pytest.raises(ValueError,match='schema'):
        reopen_workspace(workspace)


def test_logical_manifest_paths_failures_and_directories(tmp_path):
    source=tmp_path/'source.vhdx';source.write_bytes(b'synthetic')
    root=tmp_path/'run'; (root/'payload').mkdir(parents=True)
    r=row(root,'volume-A/deep/one.txt')
    manifest=dict(schema='revivex.ntfs-logical',schema_version=1,status='partial',scan_status='completed',
                  files=[dict(r, output='volume-A/deep/one.txt'),dict(name='lost.txt',status='unsupported',reason='EFS')],
                  directories=[dict(name='empty',relative_path='volume-A/deep/empty',path_reliability='logical_verified')])
    (root/'payload'/'recovery_manifest.json').write_text(json.dumps(manifest))
    result=collect_results(JobSpec('logical_ntfs',str(source),str(root)),0)
    assert result.summary['known_failed']==1 and result.summary['verified_available']==1
    with reopen_workspace(root) as catalog:
        assert catalog.count()==3
        assert catalog.query(search='one.txt')[0]['relative_path']=='volume-A/deep/one.txt'
        catalog.select_filtered()
        assert catalog.selected_count()==2
        assert catalog.export_selected(tmp_path/'export')['directories_created']==1
    args=build_arguments(JobSpec('logical_ntfs',str(source),str(root),{'max_total_bytes':1024}))
    assert args[-2:]==['--max-total-bytes','1024']


def test_actual_logical_worker_catalog_export(tmp_path):
    import time
    from revivex_jobs import JobRunner
    from test_recover_vhdx_files import ntfs_fixture
    data, expected=ntfs_fixture()
    source=tmp_path/'ntfs.img';source.write_bytes(data)
    runner=JobRunner();runner.start(JobSpec('logical_ntfs',str(source),str(tmp_path/'run'),{'source_format':'raw','max_total_bytes':1048576}))
    deadline=time.monotonic()+20
    while runner.poll() is None:
        assert time.monotonic()<deadline
        time.sleep(.01)
    result=runner.poll()
    assert result.status=='completed', result.error+result.log
    assert result.summary['verified_available']==3
    assert result.summary['original_total'] is None
    with reopen_workspace(tmp_path/'run') as catalog:
        assert catalog.count(status='directory')==3
        files=catalog.query(search='report.bin')
        assert any(r['path_reliability']=='logical_verified' for r in files)
        catalog.select_filtered()
        exported=catalog.export_selected(tmp_path/'export')
        assert exported['recovered']==3 and exported['directories_created']==3
        records=[json.loads(l) for l in Path(exported['report']).read_text().splitlines()]
        outputs=[tmp_path/'export'/r['output'] for r in records if r.get('export_status')=='copied-and-verified']
        assert any(p.read_bytes()==expected for p in outputs)


def test_gui_global_selection_keeps_failed_rows_and_run_details(tmp_path):
    import os
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    from PySide6.QtWidgets import QApplication
    from PySide6.QtCore import Qt
    from revivex_ui import MainWindow
    app=QApplication.instance() or QApplication([])
    window=MainWindow(persist_settings=False)
    window.set_language('en')
    catalog=RecoveryCatalog(tmp_path/'catalog.sqlite')
    catalog.ingest('source',[row(tmp_path,'a.txt'),row(tmp_path,'b.txt'),dict(name='lost.txt',status='failed',integrity='unavailable: CRC')])
    catalog.set_run_summary({'known_failed':1,'completeness':'known_partial'})
    window.catalog_ready(catalog)
    window.search.setText('a.txt');window.refresh_results()
    window.select_all.click()
    assert catalog.selected_count()==2
    window.clear_selection.click()
    assert catalog.selected_count()==0
    window.search.clear();window.refresh_results()
    for number in range(window.table.rowCount()):
        item=window.table.item(number,0)
        if item.text()=='lost.txt':
            assert not item.flags() & Qt.ItemFlag.ItemIsUserCheckable
    window.table.selectRow(0);app.processEvents()
    window.export_finished({'recovered':1,'failed':0,'scan_summary':{'known_failed':1}})
    assert 'known_failed' in window.details.toPlainText()
    assert 'recovered' in window.export_details.toPlainText()
    window.close();catalog.close()


def test_desktop_diagnostics_dispatches_without_qt(tmp_path):
    import subprocess
    import sys
    source=tmp_path/'damaged.vhdx';source.write_bytes(b'synthetic invalid metadata')
    report=tmp_path/'diagnostic.json'
    result=subprocess.run([sys.executable,str(Path(__file__).resolve().parents[1]/'src'/'revivex_desktop.py'),'--diagnose',str(source),'--report',str(report)],capture_output=True,text=True)
    assert report.is_file(),result.stderr
    metadata=json.loads(report.read_text())
    assert source.read_bytes()==b'synthetic invalid metadata'
    assert metadata['source_access']=='read_only'
    assert metadata['full_image_hash_performed'] is False
    assert metadata['guest_payload_scanned'] is False
    assert metadata['source_stat_unchanged'] is True


def test_metadata_only_job_lazy_export_and_resume(tmp_path):
    import time
    from revivex_jobs import JobRunner
    from test_recover_vhdx_files import ntfs_fixture
    data, expected=ntfs_fixture()
    source=tmp_path/'ntfs.img';source.write_bytes(data)
    def run(output, options):
        runner=JobRunner();runner.start(JobSpec('logical_index',str(source),str(output),options))
        deadline=time.monotonic()+20
        while runner.poll() is None:
            assert time.monotonic()<deadline
            time.sleep(.01)
        result=runner.poll()
        assert result.status=='completed', result.error+result.log
        return result
    first=run(tmp_path/'index',{'source_format':'raw'})
    assert first.summary['verified_available']==0
    assert first.summary['indexed_candidates']==3
    assert not list((tmp_path/'index'/'payload').rglob('*.bin'))
    with reopen_workspace(tmp_path/'index') as catalog:
        assert catalog.count(status='logical_candidate')==3
        catalog.select_filtered(search='report.bin')
        export=catalog.export_selected(tmp_path/'export')
        assert export['recovered']==2
        entries=[json.loads(line) for line in Path(export['report']).read_text().splitlines()]
        files=[entry for entry in entries if entry.get('export_status')=='copied-and-verified']
        assert any((tmp_path/'export'/e['output']).read_bytes()==expected for e in files)
        assert all('authenticity' in e['final_integrity'] for e in files)
    resumed=run(tmp_path/'resumed',{'source_format':'raw','resume_session':str(tmp_path/'index'/'payload'/'session.sqlite')})
    with reopen_workspace(tmp_path/'resumed') as catalog:
        assert catalog.count(status='logical_candidate')==3
        assert all(str(tmp_path/'resumed') in r['provenance']['session_path'] for r in catalog.query(status='logical_candidate'))
    source.write_bytes(b'changed')
    with reopen_workspace(tmp_path/'index') as catalog:
        catalog.select_filtered()
        result=catalog.export_selected(tmp_path/'after-change')
        assert result['recovered']==0 and result['failed']==3


def test_cancelled_index_reopens_committed_checkpoint_only(tmp_path):
    from revivex_scan_session import scan_source
    from recover_vhdx_files import Cancelled
    from test_recover_vhdx_files import ntfs_fixture
    source=tmp_path/'source.img';source.write_bytes(ntfs_fixture()[0])
    root=tmp_path/'run';(root/'payload').mkdir(parents=True)
    calls=0
    def cancel():
        nonlocal calls
        calls+=1
        return calls==24
    with pytest.raises(Cancelled):
        scan_source(source,root/'payload'/'session.sqlite',batch_size=4,cancel=cancel)
    result=collect_results(JobSpec('logical_index',str(source),str(root)),-9,cancelled=True)
    assert result.status=='cancelled' and result.summary['partial']
    assert result.summary['indexed_candidates']==3
    with reopen_workspace(root) as catalog:
        assert catalog.count(status='partial_unverified')==0
        assert catalog.count(status='logical_candidate')==3
        assert catalog.run_summary()['scan_status']=='cancelled'


def test_path_limit_message_is_platform_independent():
    import errno
    from revivex_catalog import export_error_message
    assert 'not flattened' in export_error_message(OSError(errno.ENAMETOOLONG,'too long'))
    error=OSError('Windows path limit');error.winerror=206
    assert 'shorter destination' in export_error_message(error)
    assert export_error_message(ValueError('other error'))=='other error'


def test_eighty_level_export_preserves_hierarchy_or_reports_path_limit(tmp_path):
    import os
    relative='/'.join(f'level-{n:02d}' for n in range(80))+'/same.txt'
    with RecoveryCatalog(tmp_path/'catalog.sqlite') as catalog:
        entry=row(tmp_path,'staged.bin')
        entry.update(name='same.txt',relative_path=relative)
        catalog.ingest('source',[entry]);catalog.select_filtered()
        result=catalog.export_selected(tmp_path/'export')
        report=[json.loads(line) for line in Path(result['report']).read_text().splitlines()]
        file=next(r for r in report if r.get('record')=='file')
        assert file['original_relative_path']==relative
        if result['recovered']:
            assert file['output'].replace('\\', '/').endswith(relative)  # Windows reports use backslashes
            assert (tmp_path/'export'/file['output']).read_bytes()==b'fixture'
        else:
            assert os.name=='nt'
            assert result['failed']==1
            assert 'path limit' in file['error']
            assert 'not flattened' in file['error']


def test_lazy_export_collision_preserves_competing_file_and_reports_cancel(tmp_path, monkeypatch):
    from recover_vhdx_files import Cancelled
    import revivex_scan_session
    session=tmp_path/'payload'/'session.sqlite';session.parent.mkdir();session.write_bytes(b'fixture session pointer')
    with RecoveryCatalog(tmp_path/'catalog.sqlite') as catalog:
        catalog.ingest('source',[dict(name='one.txt',relative_path='one.txt',status='logical_candidate',
            integrity='indexed: validated logical mapping; bytes not yet recovered',size=1,
            session_path=str(session),candidate_id='candidate',path_reliability='logical_verified')])
        catalog.select_filtered()
        class CollisionExporter:
            created_output=None
            created_output_identity=None
            def __init__(self,*args,**kwargs):pass
            def close(self):pass
            def export_candidate(self,candidate,path):
                path.write_bytes(b'competitor-owned')
                raise FileExistsError('Exclusive create lost race')
        monkeypatch.setattr(revivex_scan_session,'LazyExporter',CollisionExporter)
        result=catalog.export_selected(tmp_path/'collision-export')
        assert result['failed']==1 and not result['cancelled']
        assert next((tmp_path/'collision-export').rglob('one.txt')).read_bytes()==b'competitor-owned'
        class CancelExporter(CollisionExporter):
            def export_candidate(self,candidate,path):
                raise Cancelled('cancelled on final selected item')
        monkeypatch.setattr(revivex_scan_session,'LazyExporter',CancelExporter)
        result=catalog.export_selected(tmp_path/'cancel-export')
        assert result['cancelled'] and result['failed']==0 and result['recovered']==0
        records=[json.loads(line) for line in Path(result['report']).read_text().splitlines()]
        assert records[1]['export_status']=='cancelled'


def test_partial_bat_ui_is_opt_in_and_logical_only():
    import os
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    from PySide6.QtWidgets import QApplication
    from revivex_ui import MainWindow
    app=QApplication.instance() or QApplication([])
    window=MainWindow(persist_settings=False)
    assert not window.partial_bat.isChecked()
    assert window.partial_bat.isHidden()
    window.method.setCurrentIndex(window.method.findData('logical_ntfs'))
    app.processEvents()
    assert not window.partial_bat.isHidden()
    assert not window.partial_bat.isChecked()
    args=build_arguments(JobSpec('logical_index','source','output',{'allow_partial_bat':False}))
    assert '--allow-partial-bat' not in args
    args=build_arguments(JobSpec('logical_index','source','output',{'allow_partial_bat':True}))
    assert '--allow-partial-bat' in args
    window.close()
