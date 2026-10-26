"""Offscreen interaction tests: no original malware or recovered code is executed."""
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
os.environ.setdefault('XDG_CACHE_HOME', '/tmp/revivex-cache')
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
try:
    from PySide6.QtWidgets import QApplication, QMessageBox
    from PySide6.QtCore import Qt
    from PySide6.QtTest import QTest
    from revivex_ui import MainWindow
    from revivex_catalog import RecoveryCatalog
    QT = True
except ImportError:
    QT = False

@unittest.skipUnless(QT, 'PySide6 not installed')
class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.window = MainWindow(persist_settings=False)
        self.window.method.setCurrentIndex(self.window.method.findData('zip'))  # legacy ZIP flow; auto is default
        self.window.show()
        self.app.processEvents()
    def tearDown(self):
        if self.window.runner:
            self.window.runner.cancel()
            self.wait_until(lambda: not self.window.busy())
        self.window.close()
        if self.window.catalog:
            self.window.catalog.close()
        self.temp.cleanup()
    def wait_until(self, condition, timeout=15):
        end = time.monotonic() + timeout
        while not condition() and time.monotonic() < end:
            self.app.processEvents()
            time.sleep(0.01)  # Release the GIL so the Python job monitor can reconcile.
        self.assertTrue(condition())
    def catalog(self, count=405):
        catalog = RecoveryCatalog(self.root / 'catalog.sqlite')
        rows = [dict(name=f'file-{i:04d}.txt', relative_path=f'folder/sub/file-{i:04d}.txt', status='staged', path_reliability='archive', size=i, output=str(self.root / f'file-{i:04d}.txt'), integrity='verified: size and SHA-256', sha256='a'*64) for i in range(count)]
        catalog.ingest('source-one', rows, source_label='Fixture ZIP')
        self.window.catalog_ready(catalog)
        return catalog
    def test_language_theme_navigation_and_resize(self):
        w = self.window
        w.set_language('zh'); w.set_dark(True)
        self.assertEqual(w.language_box.currentIndex(), 1)
        self.assertEqual(w.theme_box.currentIndex(), 1)
        self.assertIn('开始', w.t('run'))
        w.nav_buttons[2].click()
        self.assertEqual(w.pages.currentIndex(), 2)
        w.resize(940, 690)
        self.app.processEvents()
        self.assertEqual(w.width(), 940)
        w.set_language('en'); w.method.setCurrentIndex(5)
        w.navigate(0); self.app.processEvents()
        self.assertTrue(w.pair_panel.isVisible())
        self.assertFalse(w.member_panel.isVisible())
        w.method.setCurrentIndex(6)
        self.assertTrue(w.member_panel.isVisible())
    def test_global_search_pagination_selection_shared_views(self):
        w=self.window; catalog=self.catalog()
        self.assertEqual(w.table.rowCount(), 200)
        w.select_filtered(True)
        self.assertEqual(catalog.selected_count(), 405)
        w.next.click()
        self.assertEqual(w.offset, 200)
        w.view_mode.setCurrentIndex(1)
        self.assertEqual(catalog.selected_count(), 405)
        w.view_mode.setCurrentIndex(2)
        w.search.setText('file-0404')
        self.wait_until(lambda: w.table.rowCount() == 1)
        w.clear_selection.click()
        self.assertEqual(catalog.selected_count(), 0)  # Clear all is global, even under a filter.
        self.assertEqual(w.table.item(0,0).checkState(), Qt.CheckState.Unchecked)
    def test_lazy_folder_selection(self):
        w=self.window; catalog=self.catalog(3)
        root=w.tree.topLevelItem(0)
        folder=root.child(0)
        folder.setExpanded(True)
        self.app.processEvents()
        self.assertEqual(folder.child(0).text(0), 'sub  (3)')
        folder.setCheckState(0, Qt.CheckState.Checked)
        self.assertEqual(catalog.selected_count(),3)
        w.tree.setCurrentItem(folder)
        self.assertEqual(w.table.rowCount(),3)
    def test_tree_tristate_reflects_rows_and_type_selection(self):
        w=self.window; catalog=self.catalog(3)
        w.table.item(0,0).setCheckState(Qt.CheckState.Checked)
        self.assertEqual(w.tree.topLevelItem(0).checkState(0), Qt.CheckState.PartiallyChecked)
        w.view_mode.setCurrentIndex(1)
        self.assertEqual(w.tree.topLevelItem(0).checkState(0), Qt.CheckState.PartiallyChecked)
        w.tree.topLevelItem(0).setCheckState(0, Qt.CheckState.Checked)
        self.assertEqual(catalog.selected_count(), 3)
        w.view_mode.setCurrentIndex(0)
        self.assertEqual(w.tree.topLevelItem(0).checkState(0), Qt.CheckState.Checked)

    def test_export_failure_is_never_reported_as_success(self):
        self.window.set_language('en')
        self.window.export_finished({'recovered': 1, 'failed': 2, 'cancelled': False})
        self.assertIn('failures', self.window.result_notice.text())
        self.assertIn('2 failed', self.window.result_notice.text())

    def test_validation_does_not_start_job(self):
        with patch.object(self.window, 'alert') as alert:
            self.window.start_scan()
            alert.assert_called_once()
        self.assertIsNone(self.window.runner)
    def test_actual_scan_repeated_click_and_export(self):
        source=self.root/'sample.zip'
        with zipfile.ZipFile(source,'w') as z:
            z.writestr('docs/readme.txt','safe fixture bytes')
            z.writestr('photos/index.txt','second fixture')
        original=source.read_bytes()
        w=self.window;w.source.setText(str(source));w.output.setText(str(self.root))
        w.start_scan(); first=w.runner
        w.start_scan();self.assertIs(first,w.runner)
        self.wait_until(lambda:w.runner is None and w.catalog is not None)
        self.assertEqual(source.read_bytes(),original)
        self.assertEqual(w.catalog.count(),2)
        self.assertEqual(w.pages.currentIndex(),1)
        row=w.table.item(0,0);row.setCheckState(Qt.CheckState.Checked)
        self.assertEqual(w.catalog.selected_count(),1)
        with patch('revivex_ui.QFileDialog.getExistingDirectory',return_value=str(self.root)):
            w.export_selected()
        self.wait_until(lambda:not w.busy())
        exports=list(self.root.glob('revivex-selected-*'))
        self.assertEqual(len(exports),1)
        recovered=[p for p in exports[0].rglob('*.txt')]
        self.assertEqual(len(recovered),1)
        self.assertEqual(source.read_bytes(),original)
    def test_real_scan_global_filtered_selection_and_cancel(self):
        source=self.root/'many.zip'
        with zipfile.ZipFile(source, 'w') as archive:
            for i in range(230):
                archive.writestr(f'docs/record-{i:03d}.txt', f'synthetic record {i}')
        w=self.window;w.set_language('en');w.source.setText(str(source));w.output.setText(str(self.root))
        w.start_scan()
        self.wait_until(lambda:w.runner is None and w.catalog is not None)
        self.assertEqual(w.catalog.count(),230)
        self.assertEqual(w.table.rowCount(),200)
        w.view_mode.setCurrentIndex(1);w.view_mode.setCurrentIndex(2)
        w.search.setText('record-');self.app.processEvents();w.reset_results()
        w.select_filtered(True)
        self.assertEqual(w.catalog.selected_count(),230)
        with patch('revivex_ui.QFileDialog.getExistingDirectory',return_value=str(self.root)):
            w.export_selected()
        w.cancel_job()
        self.wait_until(lambda:not w.busy())
        self.assertIn('Canceled',w.result_notice.text())
        self.assertFalse(w.cancel_button.isEnabled())
        # Real isolated subprocess cancellation and deferred window close.
        w.start_scan()
        with patch('revivex_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.Yes):
            w.close()
        self.wait_until(lambda:w.runner is None)
        self.assertTrue(w.close_pending)

    def test_close_no_preserves_running_job_and_yes_cancels(self):
        class Runner:
            running=True
            cancelled=False
            def cancel(self): self.cancelled=True
        w=self.window; runner=Runner();w.runner=runner
        with patch('revivex_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.No):
            w.close()
        self.assertTrue(w.isVisible());self.assertFalse(runner.cancelled)
        with patch('revivex_ui.QMessageBox.question',return_value=QMessageBox.StandardButton.Yes):
            w.close()
        self.assertTrue(runner.cancelled);self.assertTrue(w.close_pending)
        runner.running=False;w.runner=None

if __name__ == '__main__':
    unittest.main()
