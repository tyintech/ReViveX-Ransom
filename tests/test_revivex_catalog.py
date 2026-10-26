import hashlib
import json
from pathlib import Path
import sys
import threading
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from revivex_catalog import RecoveryCatalog


def row(tmp_path, name='one.txt', content=b'hello', **kw):
    stage=tmp_path/('stage-'+hashlib.sha256((name+str(kw)).encode()).hexdigest())
    stage.write_bytes(content)
    return dict(name=name,relative_path=name,output=str(stage),size=len(content),integrity='verified: size and SHA-256',path_reliability='archive member path (untrusted metadata)',sha256=hashlib.sha256(content).hexdigest(),**kw)


def test_pagination_filter_selection_persists(tmp_path):
    db=tmp_path/'catalog.db'
    cat=RecoveryCatalog(db)
    cat.ingest('source',(row(tmp_path,f'folder/{i:04}.txt') for i in range(507)))
    assert len(cat.query(limit=200))==200
    assert len(cat.query(offset=400,limit=200))==107
    assert cat.select_filtered(search='folder/',group='txt')==507
    cat.close(); cat=RecoveryCatalog(db)
    assert cat.selected_count()==507
    cat.select_filtered(False,search='000')
    assert cat.selected_count()==497
    first=cat.query(limit=1)[0]
    cat.ingest('source',[dict(first, id=first['provenance']['catalog_identity'])])
    assert cat.count()==507
    assert cat.query(limit=1)[0]['selected'] is False
    cat.close()


def test_folders_and_source_isolation(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        for source in ('A','B'):
            cat.ingest(source,[row(tmp_path,'x/y/same.txt'),row(tmp_path,'x/z/ü😀.txt')])
        assert cat.count()==4
        assert cat.folders(source_id='A',parent='')==[dict(source_id='A',path='x',count=2)]
        assert {r['path'] for r in cat.folders(source_id='A',parent='x')}=={'x/y','x/z'}
        cat.select_folder('A','x')
        assert cat.selected_count()==2
        cat.select_filtered(True)
        result=cat.export_selected(tmp_path/'export')
        assert result['recovered']==4
        assert len(list((tmp_path/'export').glob('*/x/y/same.txt')))==2


def test_traversal_case_ancestor_collision(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        names=['../../outside.txt','/absolute.txt','Folder/a.txt','folder/b.txt','thing','thing/child.txt','CON','ü😀.txt']
        cat.ingest('a',[row(tmp_path,n) for n in names])
        cat.select_filtered()
        result=cat.export_selected(tmp_path/'export')
        assert result['recovered']==len(names), result
        assert not (tmp_path/'outside.txt').exists()
        records=[json.loads(x) for x in Path(result['report']).read_text().splitlines()]
        for r in records:
            if r.get('export_status')=='copied-and-verified':
                assert Path(r['output']).is_absolute() is False
                assert '..' not in Path(r['output']).parts
        assert Path(result['report']).stat().st_mode & 0o222 == 0


def test_missing_damaged_unverified_and_symlink(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        missing=row(tmp_path,'missing'); Path(missing['output']).unlink()
        damaged=row(tmp_path,'damaged'); Path(damaged['output']).write_bytes(b'other')
        linked=row(tmp_path,'link'); stage=Path(linked['output']); real=stage.with_suffix('.real'); stage.rename(real); stage.symlink_to(real)
        bad=row(tmp_path,'bad'); bad['integrity']='failed: crc'
        cat.ingest('a',[missing,damaged,linked,bad]); cat.select_filtered()
        result=cat.export_selected(tmp_path/'export')
        assert result['failed']==3 and result['recovered']==0
        assert cat.selected_count()==3
        assert len([x for x in (tmp_path/'export').rglob('*') if x.is_file()])==1


def test_cancel_and_destination_protection(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        cat.ingest('a',[row(tmp_path)],source_path=str(tmp_path/'source.img')); cat.select_filtered()
        cancelled=threading.Event(); cancelled.set()
        r=cat.export_selected(tmp_path/'cancel',cancel_event=cancelled)
        assert r['cancelled'] and r['recovered']==0
        with pytest.raises(FileExistsError): cat.export_selected(tmp_path/'cancel')
        (tmp_path/'sym').symlink_to(tmp_path, target_is_directory=True)
        with pytest.raises(ValueError): cat.export_selected(tmp_path/'sym'/'export')
        with pytest.raises(ValueError): cat.export_selected(tmp_path/'source.img')


def test_unknown_paths_visible(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        r=row(tmp_path,'original.txt'); r['path_reliability']='filename only; original folders unknown'
        cat.ingest('a',[r]); result=cat.query()[0]
        assert result['relative_path']=='Unknown path/txt/original.txt'
        assert result['provenance']['relative_path']=='original.txt'


def test_unicode_search_and_inferred_badge(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        r=row(tmp_path,'München/STRAẞE.txt'); r['path_reliability']='inferred_unverified'
        cat.ingest('a',[r])
        assert cat.count(search='straße')==1
        assert cat.query()[0]['relative_path'].startswith('Inferred path/')
        with pytest.raises(ValueError,match='Select'): cat.export_selected(tmp_path/'empty')


def test_mid_copy_cancel(tmp_path):
    with RecoveryCatalog(tmp_path/'db') as cat:
        cat.ingest('a',[row(tmp_path,'big.bin',b'x'*(3*1024*1024))])
        cat.select_filtered()
        checks=0
        def cancel():
            nonlocal checks
            checks+=1
            return checks>=6
        result=cat.export_selected(tmp_path/'cancel',cancel_event=cancel)
        assert result['cancelled'] and result['recovered']==0
        assert not list((tmp_path/'cancel').rglob('big.bin'))


@pytest.mark.parametrize('digest',[None,'','not-a-hash','a'*63,'x'*64])
def test_export_requires_valid_manifest_digest(tmp_path,digest):
    with RecoveryCatalog(tmp_path/'db') as cat:
        r=row(tmp_path,'a.txt');r['sha256']=digest
        cat.ingest('a',[r]);cat.select_filtered()
        assert cat.selected_count()==0
        with pytest.raises(ValueError, match='Select at least'):
            cat.export_selected(tmp_path/'export')


def test_cleanup_failure_is_reported(tmp_path,monkeypatch):
    with RecoveryCatalog(tmp_path/'db') as cat:
        r=row(tmp_path,'bad.txt');Path(r['output']).write_bytes(b'other')
        cat.ingest('a',[r]);cat.select_filtered()
        original_unlink=Path.unlink
        def unlink(path,*args,**kwargs):
            if path.name=='bad.txt': raise PermissionError('Synthetic locked output')
            return original_unlink(path,*args,**kwargs)
        monkeypatch.setattr(Path,'unlink',unlink)
        result=cat.export_selected(tmp_path/'export')
        assert result['failed']==1
        records=[json.loads(line) for line in Path(result['report']).read_text().splitlines()]
        assert records[1]['partial_output'].endswith('bad.txt')
        assert 'Synthetic locked' in records[1]['cleanup_error']
        assert records[-1]['record']=='summary'
