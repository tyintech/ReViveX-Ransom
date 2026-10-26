"""Build an unsigned macOS app bundle (zip) from a clean committed checkout.

Output (dist/): ReViveX-Ransom-<version>-macos-<arch>.zip and SHA256SUMS-macos.txt.
The zip holds ReViveX-Ransom.app plus licenses, notices and first-launch notes.
It is not signed or notarized: Gatekeeper asks the user to allow it once.
The corresponding source is the same archive the Windows job publishes (same
commit, same pinned Qt/PySide6 versions).
"""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from windows_release import configuration, licenses, local_file, pins, run  # noqa: E402

FIRST_LAUNCH = """ReViveX Ransom for macOS (unsigned build)

首次打开 / First launch:
1. 解压后把 ReViveX-Ransom.app 拖到“应用程序”（或任意文件夹）。
   Unzip and move ReViveX-Ransom.app to Applications (or any folder).
2. 双击打开时若提示“无法验证开发者”，请打开“系统设置 › 隐私与安全性”，点“仍要打开”。
   If macOS says the developer cannot be verified, open System Settings > Privacy & Security
   and click "Open Anyway".
3. 只读取你选择的源文件；恢复结果请保存到另一块健康磁盘。
   The app only reads the source you choose; save results to a separate healthy disk.

本版本没有 Apple 开发者签名或公证。SHA256SUMS 只核对完整性，不证明发布者身份。
This build is not signed or notarized by Apple. SHA256SUMS verifies integrity, not publisher identity.
"""


def main():
    config = configuration()
    if sys.platform != 'darwin':
        raise RuntimeError('Build the macOS app on macOS')
    arch = {'arm64': 'arm64', 'x86_64': 'x64'}.get(platform.machine())
    if not arch:
        raise RuntimeError(f'Unsupported macOS architecture: {platform.machine()}')
    status = run('git', 'status', '--porcelain', stdout=subprocess.PIPE, text=True).stdout
    if status.strip():
        raise RuntimeError('Use a clean committed checkout; the app must match the published source')
    runtime = pins()
    output = ROOT / 'dist'
    output.mkdir(exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError('dist must be empty; preserve or move previous build outputs first')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED='0', QT_QPA_PLATFORM='offscreen')
    run(sys.executable, '-m', 'pytest', 'tests', 'build', '-q', env=env)
    commit = run('git', 'rev-parse', 'HEAD', stdout=subprocess.PIPE, text=True).stdout.strip()
    stem = f'ReViveX-Ransom-{config["version"]}-macos-{arch}'
    work_root = ROOT / '.build'
    work_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='macos-', dir=work_root) as temporary:
        work = Path(temporary)
        package = work / stem
        package.mkdir()
        for filename in ('LICENSE', 'NOTICE', 'README.md', 'README.en.md'):
            shutil.copyfile(local_file(filename), package / filename)
        shutil.copyfile(ROOT / 'build/QT-LIBRARY-REPLACEMENT.md', package / 'QT-LIBRARY-REPLACEMENT.md')
        (package / '首次打开说明-First-launch.txt').write_text(FIRST_LAUNCH, encoding='utf-8')
        licenses(package / 'third-party-licenses', runtime)
        from qt_sources import collect
        collect(ROOT / 'build/qt-sources.json', work / 'qt-sources', package / 'third-party-licenses' / 'Qt')
        info = {'name': config['name'], 'version': config['version'], 'commit': commit, 'python': sys.version,
                'platform': platform.platform(), 'signed': False, 'notarized': False,
                'packaging': 'PyInstaller onedir .app bundle; Qt frameworks replaceable',
                'dependencies': sorted(f'{d.metadata["Name"]}=={d.version}' for d in metadata.distributions())}
        (package / 'build-info.json').write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding='utf-8')
        args = [sys.executable, '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--windowed', '--noupx',
                '--name', 'ReViveX-Ransom', '--osx-bundle-identifier', 'com.xtyue.revivex-ransom',
                '--paths', str(ROOT / 'src'), '--distpath', str(work / 'frozen'),
                '--workpath', str(work / 'pyinstaller'), '--specpath', str(work)]
        for filename in ('LICENSE', 'NOTICE', 'README.md', 'README.en.md'):
            args += ['--add-data', f'{ROOT / filename}:.']
        args += ['--add-data', f'{package / "third-party-licenses"}:third-party-licenses']
        for source, destination in config['data_files']:
            dest = PurePosixPath(destination)
            if dest.is_absolute() or '..' in dest.parts:
                raise ValueError('Resource destination must be a safe relative path')
            args += ['--add-data', f'{local_file(source)}:{destination}']
        for module in config['hidden_imports']:
            args += ['--hidden-import', module]
        for module in ('PySide6.QtPdf', 'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtWebEngineCore'):
            args += ['--exclude-module', module]
        args.append(str(local_file(config['entry_point'])))
        run(*args, env=env)
        app = work / 'frozen' / 'ReViveX-Ransom.app'
        if not (app / 'Contents' / 'MacOS' / 'ReViveX-Ransom').is_file():
            raise RuntimeError('PyInstaller did not produce the app bundle')
        # The frozen worker, catalog and selected export must work without a display.
        run(str(app / 'Contents' / 'MacOS' / 'ReViveX-Ransom'), *config['smoke_args'], timeout=120, env=env)
        shutil.copytree(app, package / 'ReViveX-Ransom.app', symlinks=True)
        archive = output / f'{stem}.zip'
        # ditto keeps the framework symlinks and bundle metadata that zipfile would break.
        run('ditto', '-c', '-k', '--sequesterRsrc', '--keepParent', str(package), str(archive))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS-macos.txt').write_text(f'{digest}  {archive.name}\n', encoding='ascii')


if __name__ == '__main__':
    main()
