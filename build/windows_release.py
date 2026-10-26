"""Build a Windows portable EXE and its corresponding-source distribution."""
from __future__ import annotations

import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def local_file(value: str) -> Path:
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise ValueError(f"Missing or non-repository file: {value}")
    return path


def configuration():
    config = json.loads((ROOT / "build/release.json").read_text(encoding="utf-8"))
    if not re.fullmatch(r"\d+\.\d+\.\d+", config["version"]):
        raise ValueError("Release version must be X.Y.Z")
    if not config.get("entry_point"):
        raise ValueError("Complete UI entry point has not been integrated: set build/release.json entry_point")
    local_file(config["entry_point"])
    local_file("LICENSE")
    local_file("NOTICE")
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    if f'version = "{config["version"]}"' not in project:
        raise ValueError("pyproject.toml and release.json versions differ")
    identity = (ROOT / "src/revivex_info.py").read_text(encoding="utf-8")
    if f'VERSION = "{config["version"]}"' not in identity:
        raise ValueError("revivex_info.py and release.json versions differ")
    tag = os.environ.get("GITHUB_REF", "")
    if tag.startswith("refs/tags/") and tag != f'refs/tags/v{config["version"]}':
        raise ValueError("Tag and release.json versions differ")
    return config


def pins():
    values = []
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", line):
            raise ValueError(f"Runtime requirement must be an exact simple pin: {line}")
        name, version = line.split("==")
        if metadata.version(name) != version:
            raise ValueError(f"Installed version differs from runtime pin: {line}")
        values.append((name, version))
    return values


def licenses(destination: Path, runtime):
    destination.mkdir()
    for name, version in [*runtime, ("pyinstaller", metadata.version("pyinstaller"))]:
        dist = metadata.distribution(name)
        target = destination / f"{name}-{version}"
        target.mkdir()
        found = False
        for item in dist.files or []:
            parts = PurePosixPath(str(item)).parts
            if any(part.lower().startswith(("license", "copying", "copyright", "notice")) for part in parts):
                source = Path(dist.locate_file(item))
                if source.is_file():
                    # Preserve nested notices without trusting wheel paths for destinations.
                    safe = "__".join(p for p in parts if p not in ("..", ".", "/"))
                    shutil.copyfile(source, target / safe)
                    found = True
        if not found and name.lower().replace('_', '-') not in ('pyside6-essentials', 'shiboken6'):
            raise RuntimeError(f"No packaged license found for {name}; review before release")
        (target / "METADATA.txt").write_text(str(dist.metadata), encoding="utf-8")
    version = f"python{sys.version_info.major}.{sys.version_info.minor}"
    candidates = [Path(sys.base_prefix) / "LICENSE.txt", Path(sys.base_prefix) / "lib" / version / "LICENSE.txt"]
    python_license = next((c for c in candidates if c.is_file()), None)  # Windows, then macOS framework layout
    if python_license is None:
        raise RuntimeError("CPython LICENSE.txt not found")
    shutil.copyfile(python_license, destination / "Python-LICENSE.txt")
    tcl_root = Path(sys.base_prefix) / "tcl"
    for file in tcl_root.rglob("*") if tcl_root.exists() else []:
        if file.is_file() and file.name.lower().startswith(("license", "copying")):
            shutil.copyfile(file, destination / ("TclTk__" + "__".join(file.relative_to(tcl_root).parts)))


def zip_tree(source: Path, output: Path):
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())


def find_inno():
    candidates = [Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Inno Setup 6/ISCC.exe',
                  Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Inno Setup 6/ISCC.exe']
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise RuntimeError('Inno Setup 6 is not preinstalled. Install the official compiler before building.')


def audit_qt_libraries(portable):
    # An optional PDF image plugin is not part of this Widgets-only application.
    # Exclude it and its unrelated renderer rather than silently shipping QtPdf.
    for pattern in ('qpdf.dll', 'Qt6Pdf.dll'):
        for candidate in portable.rglob(pattern):
            candidate.unlink()
    allowed = {'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'Qt6Svg.dll',
               'Qt6OpenGL.dll', 'Qt6OpenGLWidgets.dll', 'Qt6Network.dll',
               'Qt6DBus.dll', 'Qt6PrintSupport.dll'}
    actual = {p.name for p in portable.rglob('Qt6*.dll')}
    if not {'Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll'} <= actual or actual - allowed:
        raise RuntimeError(f'Unexpected/missing Qt libraries; review corresponding sources: {sorted(actual)}')


def installer_smoke(installer, work, smoke_args):
    target = work / 'installed-smoke'
    run(str(installer), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/SP-',
        '/NOICONS', f'/DIR={target}', f'/LOG={work / "installer-smoke.log"}', timeout=120)
    run(str(target / 'ReViveX-Ransom.exe'), *smoke_args, timeout=60)
    # Unknown recovered/catalog files must survive uninstallation, even within app.
    sentinels = [target / 'user-catalog.sqlite', target / 'recovered' / 'example.txt']
    for sentinel in sentinels:
        sentinel.parent.mkdir(exist_ok=True)
        sentinel.write_bytes(b'user data must survive')
    run(str(target / 'unins000.exe'), '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', timeout=120)
    for _ in range(60):
        if not (target / 'ReViveX-Ransom.exe').exists():
            break
        time.sleep(0.5)
    if (target / 'ReViveX-Ransom.exe').exists() or any(p.read_bytes() != b'user data must survive' for p in sentinels):
        raise RuntimeError('Uninstall smoke failed or altered user data')


def main():
    config = configuration()
    if sys.platform != "win32" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise RuntimeError("Build on Windows x64 with 64-bit CPython; cross-compilation is unsupported")
    if sys.maxsize <= 2**32:
        raise RuntimeError("64-bit Python is required")
    status = run("git", "status", "--porcelain", stdout=subprocess.PIPE, text=True).stdout
    if status.strip():
        raise RuntimeError("Use a clean committed checkout; source archive must match the executable")
    runtime = pins()
    inno = find_inno()
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    if any(output.iterdir()):
        raise RuntimeError("dist must be empty; preserve or move previous build outputs first")
    env = dict(os.environ, PYTHONPATH=str(ROOT / "src"), PYTHONHASHSEED="0", QT_QPA_PLATFORM="offscreen")
    run(sys.executable, "-m", "pytest", "tests", "build", "-q", env=env)
    commit = run("git", "rev-parse", "HEAD", stdout=subprocess.PIPE, text=True).stdout.strip()
    work_root = ROOT / ".build"
    work_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="release-", dir=work_root) as temporary:
        work = Path(temporary)
        portable = work / "portable"
        portable.mkdir()
        for filename in ("LICENSE", "NOTICE", "README.md", "README.en.md"):
            shutil.copyfile(local_file(filename), portable / filename)
        (portable / 'build').mkdir()
        for filename in ('TESTING-0.2.md', 'README.md', 'QT-LIBRARY-REPLACEMENT.md'):
            shutil.copyfile(local_file('build/' + filename), portable / 'build' / filename)
        licenses(portable / "third-party-licenses", runtime)
        from qt_sources import collect
        qt_source_dir = work / 'qt-sources'
        collect(ROOT / 'build/qt-sources.json', qt_source_dir, portable / 'third-party-licenses' / 'Qt')
        shutil.copyfile(ROOT / 'build/QT-LIBRARY-REPLACEMENT.md', portable / 'QT-LIBRARY-REPLACEMENT.md')
        info = {
            "name": config["name"], "version": config["version"], "commit": commit,
            "python": sys.version, "platform": platform.platform(), "signed": False,
            "packaging": "onedir plus per-user installer; Qt libraries replaceable",
            "inno_compiler_sha256": hashlib.sha256(inno.read_bytes()).hexdigest(),
            "dependencies": sorted(f'{d.metadata["Name"]}=={d.version}' for d in metadata.distributions()),
        }
        (portable / "build-info.json").write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
        args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--noupx",
                "--name", "ReViveX-Ransom", "--paths", str(ROOT / "src"),
                "--distpath", str(work / 'frozen'), "--workpath", str(work / "pyinstaller"),
                "--specpath", str(work), "--console" if config["console"] else "--windowed"]
        for filename in ("LICENSE", "NOTICE", "README.md", "README.en.md"):
            args += ["--add-data", f"{ROOT / filename};."]
        args += ["--add-data", f"{portable / 'third-party-licenses'};third-party-licenses"]
        for source, destination in config["data_files"]:
            dest = PurePosixPath(destination)
            if dest.is_absolute() or ".." in dest.parts or ":" in destination or "\\" in destination:
                raise ValueError("Resource destination must be a safe relative path")
            args += ["--add-data", f"{local_file(source)};{destination}"]
        for module in config["hidden_imports"]:
            args += ["--hidden-import", module]
        for module in ('PySide6.QtPdf', 'PySide6.QtQml', 'PySide6.QtQuick', 'PySide6.QtWebEngineCore'):
            args += ['--exclude-module', module]
        args.append(str(local_file(config["entry_point"])))
        run(*args, env=env)
        shutil.copytree(work / 'frozen' / 'ReViveX-Ransom', portable, dirs_exist_ok=True)
        audit_qt_libraries(portable)
        executable = portable / "ReViveX-Ransom.exe"
        run(str(executable), *config["smoke_args"], timeout=60)
        stem = f'ReViveX-Ransom-{config["version"]}-windows-x64'
        zip_tree(portable, output / f"{stem}-portable.zip")
        installer_script = work / 'installer.iss'
        installer_script.write_text((ROOT / 'build/installer.iss').read_text(encoding='utf-8'), encoding='utf-8-sig')
        run(str(inno), f'/DAppVersion={config["version"]}', f'/DSourceDir={portable}',
            f'/DOutputDir={output}', str(installer_script))
        installer_smoke(output / f'{stem}-setup.exe', work, config['smoke_args'])
        source_root = work / "source"
        source_root.mkdir()
        run("git", "archive", "--format=zip", "--output", str(source_root / "application-source.zip"), "HEAD")
        source_deps = source_root / "dependency-sources"
        run(sys.executable, "-m", "pip", "download", "--no-deps", "--no-binary=:all:",
            "--dest", str(source_deps), *(f"{name}=={version}" for name, version in runtime
                if name.lower().replace('_', '-') not in ('pyside6-essentials', 'shiboken6')))
        shutil.copytree(qt_source_dir, source_deps / 'qt')
        shutil.copyfile(portable / "build-info.json", source_root / "build-info.json")
        (source_root / "README.txt").write_text(
            "Extract application-source.zip and follow build/README.md.\n"
            "dependency-sources contains exact runtime dependency source distributions.\n"
            "No private files, input samples, keys, or recovered data are included.\n", encoding="utf-8")
        zip_tree(source_root, output / f'ReViveX-Ransom-{config["version"]}-corresponding-source.zip')
        shutil.copyfile(portable / "build-info.json", output / "build-info.json")
    lines = []
    for path in sorted(output.iterdir()):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        lines.append(f"{digest.hexdigest()}  {path.name}\n")
    (output / "SHA256SUMS.txt").write_text("".join(lines), encoding="ascii")


if __name__ == "__main__":
    main()
