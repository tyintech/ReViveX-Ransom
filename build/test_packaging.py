"""Offline packaging guards; no build, network or publication side effects."""
import hashlib
import ast
import io
import importlib.util
import json
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load('windows_release')
publisher = load('publish_release')
qt_sources = load('qt_sources')


class PackagingTests(unittest.TestCase):
    def test_project_version_and_new_engine_packaging(self):
        root = Path(__file__).resolve().parents[1]
        release = json.loads((root / 'build/release.json').read_text())
        info = ast.parse((root / 'src/revivex_info.py').read_text(encoding='utf-8'))
        versions = [ast.literal_eval(node.value) for node in info.body
                    if isinstance(node, ast.Assign) and node.targets[0].id == 'VERSION']
        self.assertEqual(versions, [release['version']])
        project = (root / 'pyproject.toml').read_text(encoding='utf-8')
        self.assertIn(f'version = "{release["version"]}"', project)
        for module in ('recover_vhdx_files', 'revivex_vhdx', 'revivex_scan_session', 'diagnose_recovery_source'):
            self.assertIn(module, release['hidden_imports'])
            self.assertIn('"' + module + '"', project)
            self.assertTrue((root / 'src' / (module + '.py')).is_file())

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def config(self, entry='src/app.py', version='0.1.0'):
        (self.root / 'build').mkdir(exist_ok=True)
        (self.root / 'src').mkdir(exist_ok=True)
        (self.root / 'src/app.py').write_text('print("test")')
        (self.root / 'src/revivex_info.py').write_text('VERSION = "0.1.0"')
        (self.root / 'LICENSE').write_text('test license')
        (self.root / 'NOTICE').write_text('test notice')
        (self.root / 'pyproject.toml').write_text('version = "0.1.0"')
        value = {'version': version, 'entry_point': entry}
        (self.root / 'build/release.json').write_text(json.dumps(value))

    def test_missing_ui_fails_closed(self):
        self.config(entry=None)
        with patch.object(builder, 'ROOT', self.root), self.assertRaisesRegex(ValueError, 'not been integrated'):
            builder.configuration()

    def test_version_mismatch_fails(self):
        self.config(version='0.2.0')
        with patch.object(builder, 'ROOT', self.root), self.assertRaisesRegex(ValueError, 'versions differ'):
            builder.configuration()

    def test_tag_mismatch_fails(self):
        self.config()
        with patch.object(builder, 'ROOT', self.root), patch.dict(builder.os.environ, {'GITHUB_REF':'refs/tags/v9.0.0'}):
            with self.assertRaisesRegex(ValueError, 'Tag'):
                builder.configuration()

    def test_valid_configuration(self):
        self.config()
        with patch.object(builder, 'ROOT', self.root), patch.dict(builder.os.environ, {'GITHUB_REF':'refs/heads/main'}):
            self.assertEqual(builder.configuration()['version'], '0.1.0')

    def test_path_escape_fails(self):
        with patch.object(builder, 'ROOT', self.root), self.assertRaises(ValueError):
            builder.local_file('../private.txt')

    def assets(self):
        commit = 'a' * 40
        names = ['ReViveX-Ransom-0.1.0-windows-x64-setup.exe',
                 'ReViveX-Ransom-0.1.0-windows-x64-portable.zip',
                 'ReViveX-Ransom-0.1.0-corresponding-source.zip', 'build-info.json']
        lines = []
        for name in names:
            data = (json.dumps({'version':'0.1.0', 'commit':commit}).encode()
                    if name == 'build-info.json' else b'synthetic test asset')
            (self.root / name).write_bytes(data)
            lines.append(hashlib.sha256(data).hexdigest() + '  ' + name)
        (self.root / 'SHA256SUMS.txt').write_text('\n'.join(lines))
        return commit, names

    def test_valid_asset_set(self):
        commit, _ = self.assets()
        publisher.verify_assets(self.root, '0.1.0', commit)

    def test_changed_asset_rejected(self):
        commit, names = self.assets()
        (self.root / names[0]).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'Checksum mismatch'):
            publisher.verify_assets(self.root, '0.1.0', commit)

    def test_unapproved_commit_rejected(self):
        self.assets()
        with self.assertRaisesRegex(ValueError, 'approved build'):
            publisher.verify_assets(self.root, '0.1.0', 'b' * 40)

    def test_extra_asset_rejected(self):
        commit, _ = self.assets()
        (self.root / 'private.txt').write_text('not publishable')
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            publisher.verify_assets(self.root, '0.1.0', commit)

    def test_checksum_traversal_rejected(self):
        commit, _ = self.assets()
        (self.root / 'SHA256SUMS.txt').write_text('a' * 64 + '  ../private.txt\n')
        with self.assertRaisesRegex(ValueError, 'Unexpected'):
            publisher.verify_assets(self.root, '0.1.0', commit)

    def test_macos_zip_checksums_merged_and_required(self):
        commit, _ = self.assets()
        mac = 'ReViveX-Ransom-0.1.0-macos-arm64.zip'
        (self.root / mac).write_bytes(b'synthetic mac app')
        (self.root / 'SHA256SUMS-macos.txt').write_text(hashlib.sha256(b'synthetic mac app').hexdigest() + '  ' + mac + '\n')
        publisher.merge_macos_checksums(self.root)
        extra = publisher.platform_assets('0.1.0', ['windows-x64', 'macos-arm64'])
        publisher.verify_assets(self.root, '0.1.0', commit, extra)
        with self.assertRaisesRegex(ValueError, '[Uu]nexpected'):
            publisher.verify_assets(self.root, '0.1.0', commit)
        (self.root / mac).unlink()
        with self.assertRaises((ValueError, OSError)):
            publisher.verify_assets(self.root, '0.1.0', commit, extra)

    def test_macos_checksum_mismatch_rejected(self):
        self.assets()
        mac = 'ReViveX-Ransom-0.1.0-macos-arm64.zip'
        (self.root / mac).write_bytes(b'tampered')
        (self.root / 'SHA256SUMS-macos.txt').write_text('0' * 64 + '  ' + mac + '\n')
        with self.assertRaisesRegex(ValueError, 'macOS checksum mismatch'):
            publisher.merge_macos_checksums(self.root)

    def test_installer_is_per_user_without_cleanup_or_autorun(self):
        script = (Path(__file__).parent / 'installer.iss').read_text(encoding='utf-8')
        active = '\n'.join(line for line in script.splitlines() if not line.lstrip().startswith(';'))
        self.assertIn('PrivilegesRequired=lowest', active)
        self.assertNotIn('[UninstallDelete]', active)
        self.assertNotIn('[Run]', active)
        self.assertNotIn('[Registry]', active)

    def test_qt_sources_are_pinned_to_runtime_version(self):
        manifest = json.loads((Path(__file__).parent / 'qt-sources.json').read_text())
        self.assertEqual({item['version'] for item in manifest}, {'6.12.0'})
        for item in manifest:
            self.assertRegex(item['sha256'], r'^[a-f0-9]{64}$')

    def qt_archive(self, name='project/LICENSES/LGPL-3.0.txt'):
        content = io.BytesIO()
        with tarfile.open(fileobj=content, mode='w:xz') as tar:
            data = b'synthetic license notice'
            member = tarfile.TarInfo(name)
            member.size = len(data)
            tar.addfile(member, io.BytesIO(data))
        data = content.getvalue()
        manifest = self.root / 'manifest.json'
        manifest.write_text(json.dumps([{'component':'synthetic', 'version':'6.12.0',
            'url':'https://download.qt.io/official_releases/synthetic.tar.xz',
            'sha256':hashlib.sha256(data).hexdigest()}]))
        return data, manifest

    def test_qt_notice_copy_without_source_extraction(self):
        data, manifest = self.qt_archive()
        with patch.object(qt_sources.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            qt_sources.collect(manifest, self.root / 'sources', self.root / 'notices')
        notices = list((self.root / 'notices/synthetic').iterdir())
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0].read_bytes(), b'synthetic license notice')

    def test_qt_notice_traversal_rejected(self):
        data, manifest = self.qt_archive('../LICENSE.txt')
        with patch.object(qt_sources.urllib.request, 'urlopen', return_value=io.BytesIO(data)):
            with self.assertRaisesRegex(ValueError, 'Unsafe'):
                qt_sources.collect(manifest, self.root / 'sources', self.root / 'notices')

    def test_qt_unknown_dll_rejected(self):
        for name in ['Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll', 'Qt6WebEngineCore.dll']:
            (self.root / name).touch()
        with self.assertRaisesRegex(RuntimeError, 'Unexpected'):
            builder.audit_qt_libraries(self.root)


if __name__ == '__main__':
    unittest.main()
