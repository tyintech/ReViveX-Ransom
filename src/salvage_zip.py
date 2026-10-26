#!/usr/bin/env python3
"""Conservative encrypted/damaged ZIP local-record salvage. Python 3.10+ stdlib.
This is not decryption. Input bytes are never modified or executed.
Output only CRC-32 + size + complete-stream verified files.
"""
import argparse,pathlib,struct,zlib,hashlib,json,re,heapq
from revivex_source_io import BoundedSource,unpack_at

FULL_HASH_LIMIT=4*1024**3


class ActiveSpans:
    """Monotonic interval queries, newest containing header wins.

    Each interval enters/leaves each heap at most once: O(N log N),
    including crossing intervals. No historical full-list scans.
    """
    def __init__(self):
        self.pending = []
        self.active = []
        self.operations = 0

    def add(self, start, end, header):
        if start < end:
            heapq.heappush(self.pending, (start, end, header))
            self.operations += 1

    def containing(self, offset):
        while self.pending and self.pending[0][0] <= offset:
            start, end, header = heapq.heappop(self.pending)
            self.operations += 1
            if offset < end:
                heapq.heappush(self.active, (-header, start, end))
                self.operations += 1
        while self.active and self.active[0][2] <= offset:
            heapq.heappop(self.active)
            self.operations += 1
        if self.active:
            header, start, end = self.active[0]
            return start, end, -header
        return None


def collision_key(path):
    # Portable conservative naming: preserve case-only collisions on all OSes.
    return str(path.absolute()).casefold()


def output_conflict(target, used, file_keys):
    """Detect exact, case-folded and ancestor collisions before creating paths."""
    if collision_key(target) in used or target.exists():
        return True
    return any(collision_key(parent) in file_keys or (parent.exists() and not parent.is_dir())
               for parent in target.parents)


def register_output(target, root, is_directory, used, file_keys):
    used.add(collision_key(target))
    if not is_directory:
        file_keys.add(collision_key(target))
    for parent in target.parents:
        if parent == root:
            break
        used.add(collision_key(parent))


def getname(raw,flags,extra):
    name=raw.decode('utf-8' if flags&2048 else 'cp437')
    j=0
    while j+4<=len(extra):
        tag,n=struct.unpack_from('<HH',extra,j);v=extra[j+4:j+4+n];j+=4+n
        if tag==0x7075 and len(v)>=5 and v[0]==1 and struct.unpack_from('<I',v,1)[0]==zlib.crc32(raw):name=v[5:].decode('utf-8')
    if '\x00' in name or '\\' in name or ':' in name or name.startswith('/') or any(x in ('.','..') for x in name.split('/')) or not name.strip('/'):raise ValueError('unsafe name')
    parts=name.rstrip('/').split('/')
    if any(not x or any(ord(c)<32 or c in '<>"|?*' for c in x) or x.endswith((' ','.')) or re.fullmatch(r'(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])',x.split('.')[0],re.I) for x in parts):raise ValueError('unsafe Windows path component')
    if parts[0].casefold()=='_salvage_manifest.json':raise ValueError('reserved manifest path')
    return name

def inflate(src,start,compressed_size,max_size,unknown_size=False):
    d=zlib.decompressobj(-15);out=[];total=0;p=start
    limit=len(src) if unknown_size else start+compressed_size
    while p<limit:
        chunk=src[p:min(p+65536,limit)];got=d.decompress(chunk,max_size-total+1);out.append(got);total+=len(got)
        if total>max_size:raise ValueError('decompression size limit exceeded')
        if d.unconsumed_tail:raise ValueError('decompression output limit exceeded')
        consumed=len(chunk)-len(d.unused_data);p+=consumed
        if d.eof:
            if not unknown_size and p!=limit:raise ValueError('deflate trailing data')
            return b''.join(out),p
        if consumed==0:break
    raise ValueError('incomplete deflate stream')

def descriptor(src,end,compressed_size,size,prefer_zip64=False):
    pos=end+4 if src[end:end+4]==b'PK\x07\x08' else end
    formats=('<IQQ','<III') if prefer_zip64 else ('<III','<IQQ')
    for fmt in formats:
        if pos+struct.calcsize(fmt)>len(src):continue
        crc,cs,us=unpack_at(fmt,src,pos)
        if cs==compressed_size and us==size:return crc,cs,us
    raise ValueError('missing or mismatched data descriptor')

def stored_descriptor(src,start,max_size,prefer_zip64=False):
    """Find signed descriptors or unsigned descriptors at evidenced boundaries.

    Unsigned records must precede EOF or a recognized following ZIP structure.
    Size fields and incremental CRC still must agree; arbitrary boundaries are
    never guessed. Candidate count and bytes examined are bounded.
    """
    limit=min(len(src),start+max_size+24)
    candidates=set()
    position=start
    signatures=(b'PK\x03\x04',b'PK\x01\x02',b'PK\x05\x06',b'PK\x06\x06',b'PK\x06\x07')
    hits=0
    while True:
        position=src.find(b'PK',position,limit)
        if position<0:break
        hits+=1
        if hits>100000:raise ValueError('stored descriptor candidate limit exceeded')
        signature=src[position:position+4]
        if signature==b'PK\x07\x08':candidates.add(position)
        if signature in signatures:candidates.update((position-12,position-20))
        position+=2
    if len(src)<=limit:candidates.update((len(src)-12,len(src)-20))
    crc_position=start
    running_crc=zlib.crc32(b'')
    formats=('<IQQ','<III') if prefer_zip64 else ('<III','<IQQ')
    for end in sorted(candidates):
        if not start<=end<=start+max_size:continue
        size=end-start
        possibilities=[]
        if src[end:end+4]==b'PK\x07\x08':possibilities.append(end+4)
        possibilities.append(end)
        for descriptor_start in possibilities:
            for fmt in formats:
                if descriptor_start+struct.calcsize(fmt)>len(src):continue
                crc,cs,us=unpack_at(fmt,src,descriptor_start)
                if cs!=size or us!=size:continue
                while crc_position<end:
                    next_position=min(end,crc_position+65536)
                    running_crc=zlib.crc32(src[crc_position:next_position],running_crc)
                    crc_position=next_position
                if running_crc==crc:return src[start:end],end,crc,cs,us
    raise ValueError('no valid stored descriptor within evidenced boundary and size limit')

def zip64_sizes(cs,us,extra):
    if cs!=0xffffffff and us!=0xffffffff:return cs,us
    pos=0
    while pos+4<=len(extra):
        tag,length=struct.unpack_from('<HH',extra,pos);pos+=4
        value=extra[pos:pos+length];pos+=length
        if tag!=1:continue
        need=8*((us==0xffffffff)+(cs==0xffffffff))
        if len(value)<need:raise ValueError('truncated ZIP64 sizes')
        cursor=0
        if us==0xffffffff:us=struct.unpack_from('<Q',value,cursor)[0];cursor+=8
        if cs==0xffffffff:cs=struct.unpack_from('<Q',value,cursor)[0]
        return cs,us
    raise ValueError('missing ZIP64 size extra field')

def central_directory_index(src, max_entries):
    """Index bounded, structurally complete classic single-disk directories.

    This is metadata evidence, not authenticity. Every recovered payload still
    needs exact length, CRC and full stream validation. ZIP64 remains available
    through local-header salvage but is not guessed by this fallback.
    """
    result={}
    position=0
    examined=0
    eocd_hits=0
    metadata_bytes=0
    complete=True
    while True:
        end=src.find(b'PK\x05\x06',position)
        if end<0:break
        position=end+4
        eocd_hits+=1
        if eocd_hits>4096:complete=False;break
        if end+22>len(src):continue
        _,disk,cd_disk,on_disk,count,cd_size,cd_offset,comment=unpack_at('<4s4H2IH',src,end)
        if disk or cd_disk or on_disk!=count or count==65535 or end+22+comment>len(src):continue
        cd_start=end-cd_size
        base=cd_start-cd_offset
        if base<0 or cd_start<0:continue
        entries=[]
        cursor=cd_start
        valid=True
        for _ in range(count):
            examined+=1
            if examined>max_entries:complete=False;valid=False;break
            if cursor+46>end or src[cursor:cursor+4]!=b'PK\x01\x02':valid=False;break
            values=unpack_at('<4s6H3I5H2I',src,cursor)
            _,made,version,flags,method,tm,dt,crc,cs,us,nl,xl,cl,entry_disk,ia,ea,local=values
            following=cursor+46+nl+xl+cl
            if following>end or entry_disk or 0xffffffff in (cs,us,local) or not 1<=nl<=4096:
                valid=False;break
            metadata_bytes+=nl+xl+cl+46
            if metadata_bytes>64*1048576:complete=False;valid=False;break
            raw=src[cursor+46:cursor+46+nl]
            extra=src[cursor+46+nl:cursor+46+nl+xl]
            local+=base
            if not base<=local<cd_start:valid=False;break
            entries.append(dict(header_offset=local,raw=raw,extra=extra,version=version,
                flags=flags,method=method,crc=crc,cs=cs,us=us,
                symlink=((ea>>16)&0o170000)==0o120000,central_directory_offset=cd_start))
            cursor=following
        if not complete:break
        if not valid or cursor!=end:continue
        ordered=sorted({entry['header_offset'] for entry in entries})
        boundaries={offset:ordered[index+1] if index+1<len(ordered) else cd_start
                    for index,offset in enumerate(ordered)}
        for entry in entries:
            entry['next_boundary']=boundaries[entry['header_offset']]
            # Duplicate central references must agree; keep neither if ambiguous.
            old=result.get(entry['header_offset'])
            if old is not None and old!=entry:
                result[entry['header_offset']]=False
            elif old is None:result[entry['header_offset']]=entry
    return {key:value for key,value in result.items() if value},complete


def recover_central_member(src, entry, max_size):
    """Try only header-derived or adjacent-directory-derived extents."""
    off=entry['header_offset'];cs=entry['cs'];us=entry['us']
    if us>max_size or (entry['method']==0 and cs>max_size):
        raise ValueError('central member output size limit exceeded')
    candidates=[]
    if off+30<=len(src):
        nl,xl=unpack_at('<HH',src,off+26)
        ds=off+30+nl+xl
        if src[off+30:off+30+nl]==entry['raw'] and ds<=entry['next_boundary']:
            candidates.append((ds,'central_directory_and_local_name_extent'))
    # Exact next local-record/CD boundary provides an independent extent when
    # a local signature, CRC, filename length, or extra length is damaged.
    descriptor_lengths=(0,12,16,20,24) if entry['flags']&8 else (0,)
    for length in descriptor_lengths:
        candidates.append((entry['next_boundary']-length-cs,'central_directory_adjacent_boundary'))
    seen=set()
    for ds,evidence in candidates:
        if ds in seen or ds<off+30 or ds+cs>entry['next_boundary']:continue
        seen.add(ds)
        try:
            if entry['method']==8:data,end=inflate(src,ds,cs,us)
            else:data=src[ds:ds+cs];end=ds+cs
            if len(data)==us and zlib.crc32(data)==entry['crc']:
                return data,ds,end,evidence
        except (ValueError,zlib.error):pass
    raise ValueError('Central metadata could not validate any bounded payload extent')


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('input',type=pathlib.Path);ap.add_argument('output',type=pathlib.Path);ap.add_argument('--nested-output',type=pathlib.Path);ap.add_argument('--max-file-mib',type=int,default=128);ap.add_argument('--max-total-mib',type=int,default=1024);ap.add_argument('--max-input-mib',type=int,default=2048);ap.add_argument('--memory-map',action='store_true');ap.add_argument('--preserve-duplicates',action='store_true',help='Save same-name records separately under nested output/duplicates/source offset');ap.add_argument('--max-candidates',type=int,default=100000);args=ap.parse_args()
    max_file=args.max_file_mib*1048576;max_total=args.max_total_mib*1048576
    if min(max_file,max_total,args.max_input_mib,args.max_candidates)<=0:ap.error('limits must be positive')
    if args.input.stat().st_size>args.max_input_mib*1048576:ap.error('input exceeds --max-input-mib')
    if args.output.exists() and any(args.output.iterdir()):ap.error('output must be new or empty, to prevent overwriting')
    nested=args.nested_output or args.output.parent/(args.output.name+'_nested')
    if nested.exists() and any(nested.iterdir()):ap.error('nested output must be new or empty')
    if args.output.resolve()==nested.resolve() or args.output.resolve() in nested.resolve().parents or nested.resolve() in args.output.resolve().parents:ap.error('output roots must be separate, nonoverlapping directories')
    for root in (args.output,nested):
        if any(p.is_symlink() for p in [root,*root.parents]):ap.error('symlink output paths forbidden')
        root.mkdir(parents=True,exist_ok=True)
    original=args.input.stat()
    src=BoundedSource(args.input);records=[];p=0;total=0;spans=ActiveSpans();used=set();file_keys=set();scan_complete=True
    central,central_index_complete=central_directory_index(src,args.max_candidates)
    central_offsets=iter(sorted(central))
    central_next=next(central_offsets,None)
    while True:
        off=src.find(b'PK\x03\x04',p)
        if central_next is not None and (off<0 or central_next<=off):
            off=central_next;central_next=next(central_offsets,None)
        if off<0:break
        p=off+4
        if len(records)>=args.max_candidates:
            scan_complete=False;break
        record=dict(header_offset=off,status='failed')
        records.append(record)
        cinfo=central.get(off)
        central_data=None
        if cinfo:
            ver,flags,method,crc,cs,us=(cinfo[key] for key in ('version','flags','method','crc','cs','us'))
            nl=len(cinfo['raw']);el=len(cinfo['extra']);ds=off+30+nl+el
            if cinfo['symlink']:
                record.update(status='unsupported',error='Central directory marks symlink');continue
            raw_name,extra=cinfo['raw'],cinfo['extra']
        else:
            if off+30>len(src):
                record['error']='truncated local header';continue
            _,ver,flags,method,tm,dt,crc,cs,us,nl,el=unpack_at('<4s5H3I2H',src,off)
            ds=off+30+nl+el
            if not 1<=nl<=4096 or ds>len(src):
                record['error']='invalid filename length or truncated extra field';continue
            raw_name,extra=src[off+30:off+30+nl],src[off+30+nl:ds]
        if ver>63 or method not in (0,8) or flags&0x2041:
            record.update(status='unsupported',method=method,flags=flags,error='Unsupported version, encryption, or compression method');continue
        try:name=getname(raw_name,flags,extra)
        except (ValueError,UnicodeError) as error:
            record['error']=str(error);continue
        container=spans.containing(off)
        record.update(name=name,header_offset=off,data_start=ds,compressed_size=cs,size=us,flags=flags,method=method,nested_inside_header_offset=container[2] if container else None,status='failed')
        if cs and ds+cs<=len(src):spans.add(ds,ds+cs,off)
        try:
            if cinfo:
                try:
                    data,ds,end,evidence=recover_central_member(src,cinfo,min(max_file,max_total-total))
                except ValueError as central_error:
                    # An intact directory layout does not make its CRC fields
                    # infallible. Preserve independently verified local records.
                    if off+30>len(src):raise central_error
                    local=unpack_at('<4s5H3I2H',src,off)
                    if local[0]!=b'PK\x03\x04' or local[2]&0x2049 or local[3] not in (0,8):raise central_error
                    fallback=dict(cinfo,version=local[1],flags=local[2],method=local[3],crc=local[6],cs=local[7],us=local[8])
                    if src[off+30:off+30+local[-2]]!=cinfo['raw']:raise central_error
                    data,ds,end,_=recover_central_member(src,fallback,min(max_file,max_total-total))
                    crc,cs,us=fallback['crc'],fallback['cs'],fallback['us']
                    record.update(compressed_size=cs,size=us,method=fallback['method'],flags=fallback['flags'],central_metadata_conflict=True)
                    evidence='local_header_crc_after_central_metadata_conflict'
                record.update(data_start=ds,metadata_evidence=evidence,central_directory_offset=cinfo['central_directory_offset'])
                spans.add(ds,end,off)
            elif flags&8:
                if method==8:
                    data,end=inflate(src,ds,cs,min(max_file,max_total-total),True)
                    dc,dcs,dus=descriptor(src,end,end-ds,len(data),ver>=45)
                else:data,end,dc,dcs,dus=stored_descriptor(src,ds,min(max_file,max_total-total),ver>=45)
                crc=dc;cs=dcs;us=dus;record.update(compressed_size=cs,size=us)
                spans.add(ds,end,off)
            else:
                cs,us=zip64_sizes(cs,us,src[off+30+nl:ds]);record.update(compressed_size=cs,size=us)
                if cs and ds+cs<=len(src):spans.add(ds,ds+cs,off)
                if us>max_file or us+total>max_total:raise ValueError('decompression bound exceeded')
                if ds+cs>len(src):raise ValueError('compressed extent beyond input')
                if method==8:data,end=inflate(src,ds,cs,us)
                else:
                    if cs>max_file or cs+total>max_total:raise ValueError('stored member bound exceeded')
                    data=src[ds:ds+cs];end=ds+cs
            if len(data)!=us:raise ValueError('uncompressed size mismatch')
            if zlib.crc32(data)!=crc:raise ValueError('CRC32 mismatch')
            record.update(data_end=end,crc32=f'{crc:08x}')
            root=nested/str(off) if container else args.output
            target=root.joinpath(*name.rstrip('/').split('/'))
            if not target.resolve().is_relative_to(root.resolve()):raise ValueError('path escape')
            if any(q.is_symlink() for q in [target,*target.parents]):raise ValueError('symlink path forbidden')
            key=collision_key(target)
            if output_conflict(target,used,file_keys):
                if not args.preserve_duplicates:raise ValueError('duplicate output path')
                root=nested/'duplicates'/str(off)
                target=root.joinpath(*name.rstrip('/').split('/'))
                if not target.resolve().is_relative_to(root.resolve()):raise ValueError('path escape')
                if any(q.is_symlink() for q in [target,*target.parents]):raise ValueError('symlink path forbidden')
                key=collision_key(target);record['preserved_duplicate']=True
            if name.endswith('/'):
                if data:raise ValueError('nonempty directory')
                target.mkdir(parents=True,exist_ok=True);record.update(status='directory',entry_kind='directory',output=target.relative_to(nested if target.is_relative_to(nested) else args.output).as_posix(),output_root='nested' if target.is_relative_to(nested) else 'primary')
            else:
                target.parent.mkdir(parents=True,exist_ok=True)
                with target.open('xb') as f:f.write(data)
                total+=len(data);record.update(status='recovered',entry_kind='file',validation='size_crc32_complete_stream',provenance='source_bytes_only_not_original_verified',sha256=hashlib.sha256(data).hexdigest(),output=target.relative_to(nested if target.is_relative_to(nested) else args.output).as_posix(),output_root='nested' if target.is_relative_to(nested) else 'primary')
            register_output(target,root,name.endswith('/'),used,file_keys)
        except (ValueError,zlib.error,OSError) as e:record['error']=str(e)
    if len(src)<=FULL_HASH_LIMIT:
        input_digest=hashlib.sha256()
        for offset in range(0,len(src),8*1048576):input_digest.update(src[offset:offset+8*1048576])
        input_sha256=input_digest.hexdigest();input_hash_status='computed_full_input'
    else:input_sha256=None;input_hash_status='skipped_large_source_stat_identity_only'
    final=args.input.stat()
    unchanged=(original.st_size,original.st_mtime_ns)==(final.st_size,final.st_mtime_ns)
    good=[r for r in records if r['status']=='recovered'];summary=dict(schema='revivex.zip-salvage',schema_version=1,status='completed_partial_salvage' if scan_complete and unchanged else 'incomplete',scan_complete=scan_complete,central_index_complete=central_index_complete,central_indexed_entries=len(central),source_size_and_mtime_unchanged=unchanged,span_index_operations=spans.operations,unsupported_visible_candidates=sum(r['status']=='unsupported' for r in records),input=str(args.input),input_sha256=input_sha256,input_hash_status=input_hash_status,recovered_files=len(good),recovered_bytes=total,outer_files=sum(r['nested_inside_header_offset'] is None for r in good),nested_files=sum(r['nested_inside_header_offset'] is not None for r in good),directory_records=sum(r['status']=='directory' for r in records),failed_visible_candidates=sum(r['status']=='failed' for r in records),warning='Not decryption. Entries with encrypted local headers are invisible here, so failed candidate count is NOT a count of every unrecovered file. No original input was used. Raw nested-containment classification is heuristic. Partial-stream recovery is not included in this tool. Outputs are ordinary files only, never symlinks; do not execute recovered files without malware scanning.',records=records)
    summary['files_scope']='primary_root_only; records and overall counts also include nested root'
    summary['files']=[record for record in records if record.get('output_root')=='primary' and record['status'] in ('recovered','directory')]
    summary['nested_manifest']=str(nested/'_salvage_manifest.json')
    nested_summary={key:value for key,value in summary.items() if key not in ('files','records','nested_manifest')}
    nested_summary['files']=[record for record in records if record.get('output_root')=='nested' and record['status'] in ('recovered','directory')]
    nested_summary['scope']='nested_and_duplicate_outputs_only'
    nested_summary['files_scope']='this_manifest_root_only'
    nested_summary['recovered_files']=sum(record['status']=='recovered' for record in nested_summary['files'])
    nested_summary['recovered_bytes']=sum(record['size'] for record in nested_summary['files'])
    for key in ('outer_files','nested_files','directory_records','failed_visible_candidates','unsupported_visible_candidates'):
        nested_summary.pop(key,None)
    with (nested/'_salvage_manifest.json').open('x',encoding='utf-8') as stream:
        json.dump(nested_summary,stream,ensure_ascii=True,indent=2)
    src.close()
    with (args.output/'_salvage_manifest.json').open('x',encoding='utf-8') as f:f.write(json.dumps(summary,ensure_ascii=False,indent=2))
    print(json.dumps({k:v for k,v in summary.items() if k not in ('records','files')},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
