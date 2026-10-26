import os
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
import pytest
from PySide6.QtWidgets import QApplication, QScrollArea, QPushButton, QLabel
from PySide6.QtCore import QPoint
from revivex_ui import MainWindow

@pytest.fixture(scope='module')
def app():
    return QApplication.instance() or QApplication([])

@pytest.mark.parametrize('size', [(960,640),(1000,700),(1280,720),(1536,864)])
@pytest.mark.parametrize('language', ['zh','en'])
def test_pages_fit_without_outer_scrolling(app, size, language):
    window=MainWindow(persist_settings=False)
    window.set_language(language)
    window.resize(*size)
    window.show()
    try:
        for page_index in range(4):
            window.navigate(page_index)
            app.processEvents()
            page=window.pages.currentWidget()
            assert window.width() <= size[0] and window.height() <= size[1], (window.size(),size)
            assert not isinstance(page,QScrollArea), 'Whole pages must not scroll'
            for button in page.findChildren(QPushButton):
                if not button.isVisible(): continue
                origin=button.mapTo(page,QPoint(0,0))
                assert origin.x() >= 0 and origin.y() >= 0, button.text()
                assert origin.x()+button.width() <= page.width(), button.text()
                assert origin.y()+button.height() <= page.height(), button.text()
        window.navigate(0)
        for index in range(window.method.count()):
            window.method.setCurrentIndex(index)
            app.processEvents()
            page=window.pages.currentWidget()
            y=window.run_button.mapTo(page,QPoint(0,0)).y()
            assert y+window.run_button.height() <= page.height()
            for label in page.findChildren(QLabel):
                if label.isVisible() and label.wordWrap():
                    assert label.height() >= label.heightForWidth(label.width()), label.text()
    finally:
        window.close()
