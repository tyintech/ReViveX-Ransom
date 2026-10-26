"""Collect exact Qt sources and notices; never extract executable source files."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request


def collect(manifest: Path, sources: Path, notices: Path):
    sources.mkdir(parents=True, exist_ok=True)
    notices.mkdir(parents=True, exist_ok=True)
    entries = json.loads(manifest.read_text(encoding='utf-8'))
    for item in entries:
        url = item['url']
        if not url.startswith('https://download.qt.io/official_releases/'):
            raise ValueError('Qt sources must use the reviewed official download endpoint')
        archive = sources / url.rsplit('/', 1)[1]
        digest = hashlib.sha256()
        with urllib.request.urlopen(url, timeout=120) as response, archive.open('xb') as output:
            total = 0
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > 256 * 1024 * 1024:
                    raise ValueError('Source archive exceeds reviewed size limit')
                output.write(block)
                digest.update(block)
        if digest.hexdigest() != item['sha256']:
            raise ValueError(f'Qt source checksum mismatch: {archive.name}')
        target = notices / item['component']
        target.mkdir()
        count = 0
        with tarfile.open(archive, 'r:xz') as stream:
            for member in stream:
                path = PurePosixPath(member.name)
                if not member.isfile() or member.size > 2 * 1024 * 1024:
                    continue
                parts = path.parts
                wanted = any(p.lower().startswith(('license', 'copying', 'copyright', 'notice')) for p in parts)
                wanted = wanted or path.name in ('qt_attribution.json', 'REUSE.toml')
                if wanted:
                    if path.is_absolute() or '..' in parts:
                        raise ValueError('Unsafe source notice path')
                    # Hash prefix avoids Windows path/name length limits and collisions.
                    name = hashlib.sha256(member.name.encode()).hexdigest()[:16] + '-' + path.name
                    data = stream.extractfile(member).read()
                    (target / name).write_bytes(data)
                    count += 1
        if not count:
            raise RuntimeError(f'No source notices collected for {item["component"]}')
    (notices / 'source-manifest.json').write_text(json.dumps(entries, indent=2), encoding='utf-8')
