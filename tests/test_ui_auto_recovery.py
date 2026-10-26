import json
import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
from pathlib import Path
from unittest.mock import patch
from PySide6.QtWidgets import QApplication, QScrollArea, QPushButton, QLabel
from PySide6.QtCore import QPoint
from revivex_ui import MainWindow
from revivex_ui_text import ACTIONS, TEXT


@pytest.fixture(scope='module')
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    w = MainWindow(persist_settings=False)
    w.set_language('zh')
    yield w
    w.close()


PROGRESS = dict(stage='raw_scan', stage_index=3, stage_count=4, status='running', scanned_bytes=3 * 1024 ** 3,
                planned_bytes=12 * 1024 ** 3, bytes_per_second=100 * 1024 ** 2, verified_files=5,
                candidates=9, failed=1, duplicates=0, unsupported=0, extra_read_bytes=0, message='', updated_at=1.0)


def start(window, tmp_path, progress=None):
    src = tmp_path / 'src.bin'
    src.write_bytes(b'x')
    out = tmp_path / 'out'
    out.mkdir()
    window.source.setText(str(src))
    window.output.setText(str(out))
    window.max_file.setValue(7)
    window.max_total.setValue(99)
    calls = []
    with patch.object(MainWindow, 'begin_job', lambda self, *a: calls.append(a)):
        window.start_scan()
    return calls


def test_auto_first_default_and_text(window):
    assert ACTIONS[0] == 'auto'
    assert window.method.currentData() == 'auto' and window.method.currentIndex() == 0
    assert window.method.itemText(0) == '自动恢复（推荐）'
    assert window.run_button.text() == '开始自动恢复'
    assert window.limit_panel.isVisibleTo(window)
    window.set_language('en')
    assert window.method.itemText(0) == 'Automatic recovery (recommended)'
    assert window.run_button.text() == 'Start automatic recovery'
    assert 'never guaranteed' in window.method_description.text()
    assert window.method.count() == 8
    window.method.setCurrentIndex(1)
    assert window.method.currentData() == 'zip'


def test_begin_job_called_with_auto_and_limits(window, tmp_path):
    calls = start(window, tmp_path)
    assert len(calls) == 1
    tool, source, output, options = calls[0]
    assert tool == 'auto'
    assert options == {'max_file_mib': 7, 'max_total_mib': 99}


def test_progress_rendering_and_polling(window, tmp_path):
    window.start_auto_progress(str(tmp_path))
    assert window.auto_timer.interval() == 750 and window.auto_timer.isActive()
    (tmp_path / 'progress.json').write_text(json.dumps(PROGRESS))
    window.poll_auto_progress()
    assert '阶段 3/4 · 原始字节扫描' in window.auto_stage_label.text()
    assert '已扫描 3.0 GiB / 计划 12.0 GiB' in window.auto_bytes_label.text()
    assert '100.0 MiB/秒' in window.auto_bytes_label.text()
    assert '预计剩余' in window.auto_bytes_label.text()
    assert '已验证 5 · 候选 9 · 失败 1' in window.auto_counts_label.text()
    assert (window.progress.minimum(), window.progress.maximum(), window.progress.value()) == (0, 1000, 250)
    window.set_language('en')
    assert 'Stage 3/4 · Raw byte scan' in window.auto_stage_label.text()
    assert 'Scanned 3.0 GiB / planned 12.0 GiB' in window.auto_bytes_label.text()
    window.stop_auto_progress()
    assert not window.auto_timer.isActive() and not window.auto_panel.isVisibleTo(window)


def test_null_speed_and_planned(window, tmp_path):
    window.start_auto_progress(str(tmp_path))
    data = dict(PROGRESS, bytes_per_second=None, planned_bytes=None)
    (tmp_path / 'progress.json').write_text(json.dumps(data))
    window.poll_auto_progress()
    text = window.auto_bytes_label.text()
    assert '速度' not in text and '预计' not in text
    assert window.progress.maximum() == 0  # indeterminate
    (tmp_path / 'progress.json').write_text(json.dumps(dict(PROGRESS, bytes_per_second=None)))
    window.poll_auto_progress()
    assert '速度' not in window.auto_bytes_label.text() and '预计' not in window.auto_bytes_label.text()
    assert window.progress.maximum() == 1000


def test_missing_and_corrupt_keep_last_good(window, tmp_path):
    window.start_auto_progress(str(tmp_path))
    window.poll_auto_progress()  # missing
    assert window.auto_stage_label.text() == '准备中…'
    path = tmp_path / 'progress.json'
    path.write_text(json.dumps(PROGRESS))
    window.poll_auto_progress()
    good = window.auto_bytes_label.text()
    path.write_text('{"stage": "raw_sc')
    window.poll_auto_progress()
    assert window.auto_bytes_label.text() == good
    path.write_bytes(b'\xff\xfe\x00')
    window.poll_auto_progress()
    path.write_text('[1,2]')
    window.poll_auto_progress()
    assert window.auto_bytes_label.text() == good
    path.unlink()
    window.poll_auto_progress()
    assert window.auto_bytes_label.text() == good


def test_no_rate_wording(window, tmp_path):
    window.start_auto_progress(str(tmp_path))
    (tmp_path / 'progress.json').write_text(json.dumps(PROGRESS))
    window.poll_auto_progress()
    for language in ('zh', 'en'):
        window.set_language(language)
        shown = ' '.join([window.auto_stage_label.text(), window.auto_bytes_label.text(),
                          window.auto_counts_label.text(), window.method_description.text()]).lower()
        assert '恢复率' not in shown and '完整率' not in shown and 'recovery rate' not in shown and '%' not in shown
        for key, value in TEXT[language].items():
            if key.startswith(('auto', 'stage_', 'run_auto')):
                assert '恢复率' not in value and 'rate' not in value.lower().replace('integrate', '')


@pytest.mark.parametrize('size', [(960, 640), (1000, 700), (1280, 720), (1536, 864)])
@pytest.mark.parametrize('language', ['zh', 'en'])
def test_auto_layout_with_progress_panel(app, tmp_path, size, language):
    window = MainWindow(persist_settings=False)
    window.set_language(language)
    window.resize(*size)
    window.show()
    try:
        window.navigate(0)
        window.method.setCurrentIndex(0)
        window.start_auto_progress(str(tmp_path))
        (tmp_path / 'progress.json').write_text(json.dumps(PROGRESS))
        window.poll_auto_progress()
        window.set_busy(True)
        app.processEvents()
        page = window.pages.currentWidget()
        assert not isinstance(page, QScrollArea)
        assert window.width() <= size[0] and window.height() <= size[1]
        assert window.auto_panel.isVisible()
        for button in page.findChildren(QPushButton):
            if not button.isVisible():
                continue
            origin = button.mapTo(page, QPoint(0, 0))
            assert origin.x() >= 0 and origin.y() >= 0, button.text()
            assert origin.x() + button.width() <= page.width(), button.text()
            assert origin.y() + button.height() <= page.height(), button.text()
        for widget in (window.auto_panel, window.progress, window.limit_panel, window.method_description):
            origin = widget.mapTo(page, QPoint(0, 0))
            assert origin.y() >= 0 and origin.y() + widget.height() <= page.height(), widget
        for lab in page.findChildren(QLabel):
            if lab.isVisible() and lab.wordWrap():
                assert lab.height() >= lab.heightForWidth(lab.width()), lab.text()
    finally:
        window.set_busy(False)
        window.close()
