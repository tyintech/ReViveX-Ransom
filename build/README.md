# Windows release maintenance

## 0.2.0 validation gate

Version is 0.2.0 in release.json, pyproject.toml and revivex_info.py. Publication
remains `none` while integration and real-image/Windows validation are pending.
The earlier 0.1 source snapshot is not a final binary release. New modules
`recover_vhdx_files`, `revivex_vhdx`, `revivex_scan_session` and
`diagnose_recovery_source` are included in module packaging and hidden imports.
The strict VHDX reader uses the standard library; no new runtime dependency
is added. Disk-backed session core and desktop/workspace integration tests pass;
clean Windows and real-image validation remain required. See [large-image testing](TESTING-0.2.md).

Run the full pytest suite (including plain-function tests), not unittest-only
discovery. Revalidate frozen dynamic imports and installer tests after changing
an engine. Keep rejection tests for active logs, differencing chains, unsupported
NTFS geometry/features, bounds and incomplete scans. Synthetic fixtures do not
substitute for a clean-Windows, real-image test. Do not mount or modify fixtures
or evidence, and do not package private images or recovered data.

Build on Windows x64 with CPython 3.12 (source tools require Python 3.10+).
PyInstaller is not a cross-compiler. A Linux build is not a Windows EXE.

## Integration gate

`release.json` selects `src/revivex_desktop.py`. Set `entry_point` to null to
disable binary creation during an incomplete integration. The entry supports
`--self-test`, finishes promptly with exit
code 0, and exercise imports/resources without opening a GUI, scanning disks,
accessing private data, or modifying user files. Include dynamic imports in
`hidden_imports` and resource mappings as `["source/path", "destination"]`
pairs in `data_files`. Keep all runtime dependencies pinned in requirements.txt
and pyproject.toml. Do not import a CLI-only module that parses argv at import.

## Build

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-build.txt
$env:PYTHONPATH = 'src'
$env:QT_QPA_PLATFORM = 'offscreen'
.venv\Scripts\python -m pytest tests build -q
.venv\Scripts\python build\windows_release.py
```

The build refuses missing entry points/licenses, mismatched version/tag,
dirty tracked files, failed tests, failed frozen smoke checks or missing
third-party licenses. Use a clean committed checkout. Generated files go to
`dist/` and `.build/`, never to a fixed drive or user input folder.

Outputs: an unsigned per-user installer EXE, an onedir portable ZIP with readable
licenses/documentation and replaceable Qt DLLs, a corresponding-source ZIP with
pinned runtime dependency sources, SHA256SUMS.txt, and build provenance metadata.
The portable EXE requires the accompanying `_internal` directory: distribute
the full ZIP, never that launcher by itself. The installer uses the current
user's LocalAppData Programs folder, adds an uninstaller/Start-menu shortcut,
and offers an optional desktop shortcut. It does not request administrator
rights, add services/autorun, start scans or launch the app automatically.
Uninstall removes only installed program files; it has no wildcard delete
or catalog/recovered-data cleanup. The build smoke-tests install/uninstall
with synthetic user-data sentinels. Inno Setup 6 must already be installed;
GitHub's Windows runner includes it. No compiler installer is silently fetched.
Keep the portable ZIP and corresponding-source ZIP together
when mirroring releases. A checksum confirms integrity, not publisher identity.

## CI and publication

The workflow tests on Python 3.10 and 3.12 on Windows on pushes and pull
requests. Once entry_point is set, main pushes also build downloadable Actions
artifacts. Manual dispatch uses the same configuration. `release_stage` in
release.json controls publication: `none` (default) creates no release; `draft`
creates a new draft release, refusing an existing version; `publish` promotes
that existing draft without replacing any assets. Before selecting `publish`,
inspect the draft assets, complete a clean Windows UI smoke test, and set
`publish_commit` to the exact 40-character commit in its build-info.json.
Promotion re-downloads and verifies the existing draft's complete asset set,
checksums and approved commit. It does not rebuild or substitute binaries.
Already-public releases are left untouched. Reset the gate to `none` after
publication and bump the version before preparing the next release.

Tags `vX.Y.Z` trigger a draft when the gate is `none`; tag/version mismatch
fails. A missing UI entry point prevents release. Source-only main pushes
with entry_point null run the tests and deliberately skip binary creation.
No personal access token or signing certificate is required: the release job
uses the repository-scoped GitHub Actions token. No Authenticode signing is
claimed. Do not tell users to turn off Defender or bypass security warnings.

## License review

The application is AGPL-3.0-or-later, approved by its author. Keep the full
LICENSE, NOTICE, dependency notices, build scripts, and exact matching source
available beside every binary. Review any new dependency before adding it.
Pillow (MIT-CMU) and pypdf (BSD-3-Clause) were reviewed but are not current runtime
dependencies; if added, their notices and any bundled native-library notices
must also be included. The source bundle is not a warranty of legal compliance
for future changes.

Qt/PySide6 Essentials/Shiboken6 6.12.0 use LGPLv3. The app dynamically loads
replaceable DLLs; see [replacement instructions](QT-LIBRARY-REPLACEMENT.md).
`qt-sources.json` pins official Qt/PySide source archives and SHA256 digests.
The release includes those source archives and extracts their original
copyright/license/attribution files into `third-party-licenses/Qt`.
PySide wheels do not ship all these notices, so metadata alone is not enough.
Only reviewed QtBase, Svg, ImageFormats and translation libraries/resources
are allowed; unused QtPdf plugins are removed and unexpected Qt DLLs fail the
build pending license/source review. Adding QML, WebEngine or other modules
requires updating this source/notices contract first.

Upstream primary sources:
- https://github.com/fox-it/dissect.ntfs/blob/main/pyproject.toml
- https://github.com/fox-it/dissect.cstruct/blob/main/pyproject.toml
- https://github.com/fox-it/dissect.util/blob/main/pyproject.toml
- https://github.com/python-pillow/Pillow/blob/main/LICENSE
- https://github.com/py-pdf/pypdf/blob/main/LICENSE
- https://pyinstaller.org/en/stable/license.html
- https://www.qt.io/development/open-source-lgpl-obligations
- https://doc.qt.io/qtforpython-6/licenses.html
- https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm
- https://jrsoftware.org/ishelp/topic_uninstalldeletesection.htm

Action pins were verified against official release pages: checkout v7.0.1,
setup-python v6.0.0, upload-artifact v4.6.2, download-artifact v4.3.0. Dependency versions are pinned,
but this is not a bit-for-bit reproducible build claim: hosted runner images
and build-tool transitive dependencies can change. build-info.json records
the exact environment used. Review and update pins regularly.

## Large-fixture safety in Windows CI

Tests use `tests/sparse_fixtures.py` to mark only newly generated, small fixture
files inside dedicated temporary test directories sparse before increasing
logical length. On Windows the helper invokes `FSCTL_SET_SPARSE` with NULL input
on the fixture handle; it does not require elevation or change system settings.
Failure explicitly skips before truncation, never falling back to allocating
GiB/TiB of zeros. No production source/evidence path calls this helper. POSIX
uses hole-preserving truncate. Fake Win32-call tests run on Linux; the real
Windows sparse-attribute test must run in Windows CI.

Reference: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_sparse
