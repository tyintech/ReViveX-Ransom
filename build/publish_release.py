"""Create an immutable draft or explicitly promote the reviewed draft."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def gh(*args):
    return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout


def platform_assets(version, platforms):
    return {f'ReViveX-Ransom-{version}-{name}.zip' for name in platforms if name.startswith('macos-')}


def merge_macos_checksums(root):
    """Fold the macOS job's checksum file into SHA256SUMS.txt after checking it."""
    extra = root / 'SHA256SUMS-macos.txt'
    if not extra.is_file():
        return
    lines = extra.read_text(encoding='ascii').splitlines()
    for line in lines:
        digest, filename = line.split('  ', 1)
        if '/' in filename or '\\' in filename or hashlib.sha256((root / filename).read_bytes()).hexdigest() != digest:
            raise ValueError('macOS checksum mismatch')
    sums = root / 'SHA256SUMS.txt'
    existing = sums.read_text(encoding='ascii')
    if existing and not existing.endswith('\n'):
        existing += '\n'
    sums.write_text(existing + ''.join(line + '\n' for line in lines), encoding='ascii')
    extra.unlink()


def verify_assets(root, version, commit, extra=()):
    stem = f'ReViveX-Ransom-{version}-windows-x64'
    expected = {f'{stem}-setup.exe', f'{stem}-portable.zip',
                f'ReViveX-Ransom-{version}-corresponding-source.zip', 'build-info.json', *extra}
    seen = set()
    for line in (root / 'SHA256SUMS.txt').read_text(encoding='ascii').splitlines():
        digest, filename = line.split('  ', 1)
        if filename not in expected or filename in seen or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('Unexpected or duplicate checksum entry')
        h = hashlib.sha256()
        with (root / filename).open('rb') as f:
            for block in iter(lambda: f.read(1024 * 1024), b''):
                h.update(block)
        if h.hexdigest() != digest:
            raise ValueError(f'Checksum mismatch: {filename}')
        seen.add(filename)
    if seen != expected or {p.name for p in root.iterdir()} != expected | {'SHA256SUMS.txt'}:
        raise ValueError('Release asset set is incomplete or unexpected')
    info = json.loads((root / 'build-info.json').read_text(encoding='utf-8'))
    if info['version'] != version or info['commit'] != commit:
        raise ValueError('Asset version/commit does not match approved build')


def main():
    config = json.loads(Path('build/release.json').read_text(encoding='utf-8'))
    version = config['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid version')
    tag = 'v' + version
    stage = os.environ['RELEASE_STAGE']
    extra = platform_assets(version, config.get('platforms', []))
    if stage == 'draft':
        commit = os.environ['GITHUB_SHA']
        root = Path('dist')
        merge_macos_checksums(root)
        verify_assets(root, version, commit, extra)
        # gh release create fails if the release already exists; never use --clobber.
        # Do not attach a new binary to an existing tag pointing at another commit.
        ref = subprocess.run(['gh', 'api', f'repos/{os.environ["GH_REPO"]}/git/ref/tags/{tag}'],
                             capture_output=True, text=True)
        if ref.returncode == 0:
            obj = json.loads(ref.stdout)['object']
            while obj['type'] == 'tag':
                obj = json.loads(gh('api', f'repos/{os.environ["GH_REPO"]}/git/tags/{obj["sha"]}'))['object']
            if obj['type'] != 'commit' or obj['sha'] != commit:
                raise ValueError('Existing tag points at a different commit; bump the version')
        elif '404' not in ref.stderr:
            raise RuntimeError('Cannot verify existing tag: ' + ref.stderr)
        notes = (
            'Windows x64 installer and portable build; macOS (Apple silicon) app zip.\n'
            'Windows x64 安装包与免安装版；macOS（Apple 芯片）应用压缩包。\n\n'
            'macOS: unsigned and not notarized; allow it once in System Settings > Privacy & Security.\n'
            'macOS 版未签名、未公证：首次打开需在“系统设置 › 隐私与安全性”中点“仍要打开”。\n\n'
            'Download the portable ZIP for EXE, documentation and licenses. '
            'The matching corresponding-source ZIP is provided alongside it under AGPL-3.0-or-later.\n'
            '下载 portable.zip 获取程序、说明和许可证；同页 corresponding-source.zip 提供对应源码。\n\n'
            'Unsigned build. SHA256SUMS.txt verifies integrity, not publisher identity. '
            'Recovery is not guaranteed; work on copies.\n'
            '未进行数字签名。SHA256 可核对完整性，不代表发布者身份验证。恢复不保证成功，请处理副本。\n\n'
            f'Build commit: {commit}\n'
        )
        gh('release', 'create', tag, '--draft', '--target', commit, '--title', f'ReViveX Ransom {version}',
           '--notes', notes, *(str(p) for p in sorted(root.iterdir())))
    elif stage == 'publish':
        approved = config.get('publish_commit')
        if not isinstance(approved, str) or not re.fullmatch('[0-9a-f]{40}', approved):
            raise ValueError('Set publish_commit to the exact reviewed draft build commit')
        release = json.loads(gh('release', 'view', tag, '--json', 'isDraft,targetCommitish,tagName'))
        if not release['isDraft']:
            print('Release is already public; immutable assets were left unchanged.')
            return
        if release['targetCommitish'] != approved or release['tagName'] != tag:
            raise ValueError('Draft target does not match the explicitly reviewed commit')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            gh('release', 'download', tag, '--dir', str(root))
            verify_assets(root, version, approved, extra)
        gh('release', 'edit', tag, '--draft=false', '--latest')
    else:
        raise ValueError('Publication requires draft or publish stage')


if __name__ == '__main__':
    main()
