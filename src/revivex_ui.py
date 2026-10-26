"""Bilingual, nonblocking Qt Widgets recovery workspace.

No recovered file is opened or executed. Scans explicitly stage extracted data;
selection across views controls the subsequent copy to a fresh export directory.
"""
from __future__ import annotations
import json
import locale
import sys
import uuid
from pathlib import Path
from datetime import datetime
from PySide6.QtCore import Qt, QTimer, QThread, Signal, QSettings, QLocale
from PySide6.QtWidgets import (QMainWindow, QWidget, QFrame, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QLineEdit, QComboBox, QFileDialog,
    QStackedWidget, QTabWidget, QCheckBox, QSpinBox, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QMessageBox, QTreeWidget,
    QTreeWidgetItem, QSplitter, QAbstractItemView, QDialog, QAbstractSpinBox, QStyledItemDelegate, QStyleOptionViewItem, QStyle)
from PySide6.QtGui import QPainter, QPen, QColor, QPainterPath
from revivex_ui_text import TEXT, ACTIONS
from revivex_ui_theme import stylesheet
import revivex_info as info


class ChevronComboBox(QComboBox):
    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor('#8195a6'), 1.6))
        x, y = self.width() - 18, self.height() // 2
        painter.drawLine(x - 4, y - 2, x, y + 2)
        painter.drawLine(x, y + 2, x + 4, y - 2)


QComboBox = ChevronComboBox


class SelectionDelegate(QStyledItemDelegate):
    """Keep native item semantics, with high-contrast custom selection marks."""
    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
    def paint(self, painter, option, index):
        super().paint(painter, option, index)
        state = index.data(Qt.ItemDataRole.CheckStateRole)
        if state is None:
            return
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        rect = opt.widget.style().subElementRect(QStyle.SubElement.SE_ItemViewItemCheckIndicator, opt, opt.widget)
        if not rect.isValid():
            return
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        accent = QColor('#75d4c0' if self.window.dark else '#087e71')
        painter.setPen(QPen(accent if state else QColor('#8195a6'), 1.2))
        painter.setBrush(accent if state else QColor('#17232f' if self.window.dark else '#ffffff'))
        painter.drawRoundedRect(rect.adjusted(1, 1, -1, -1), 2, 2)
        if state:
            painter.setPen(QPen(QColor('#102b29' if self.window.dark else '#ffffff'), 1.8))
            x, y = rect.x(), rect.y()
            if state == Qt.CheckState.PartiallyChecked.value:
                painter.drawLine(x + 4, y + rect.height() // 2, rect.right() - 3, y + rect.height() // 2)
            else:
                path = QPainterPath()
                path.moveTo(x + 3, y + rect.height() * .5)
                path.lineTo(x + rect.width() * .43, rect.bottom() - 3)
                path.lineTo(rect.right() - 2, y + 3)
                painter.drawPath(path)
        painter.restore()


class TaskThread(QThread):
    result = Signal(object)
    failed = Signal(str)
    def __init__(self, work, parent=None):
        super().__init__(parent)
        self.work = work
    def run(self):
        try:
            self.result.emit(self.work())
        except Exception as exc:
            self.failed.emit(str(exc))


def label(text='', role='', wrap=False):
    widget = QLabel(text)
    widget.setObjectName(role)
    widget.setWordWrap(wrap)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    return widget


def card():
    frame = QFrame()
    frame.setObjectName('card')
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(24, 20, 24, 22)
    layout.setSpacing(14)
    return frame, layout


class MainWindow(QMainWindow):
    PAGE_SIZE = 200
    def __init__(self, persist_settings=True):
        super().__init__()
        self.settings = QSettings('ReViveX', 'ReViveX Ransom') if persist_settings else None
        self.language = 'zh' if QLocale.system().name().lower().startswith('zh') else 'en'
        if self.settings:
            saved_language = self.settings.value('language', self.language)
            self.language = saved_language if saved_language in TEXT else self.language
        initial_dark = self.settings.value('dark', False, type=bool) if self.settings else False
        self.dark = initial_dark
        self.runner = None
        self.catalog = None
        self.run_summary = {}
        self.worker = None
        self.close_pending = False
        self._operation_active = False
        self.offset = 0
        self.filter_kind = None
        self.filter_value = None
        self.filter_source = None
        self._refreshing = False
        self._texts = []
        self._placeholders = []
        self.last_output = ''
        self.setWindowTitle(f'{info.NAME}  {info.VERSION}')
        self.setMinimumSize(940, 600)
        self._compact = None
        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.setCentralWidget(root)
        sidebar = QFrame()
        self.sidebar = sidebar
        sidebar.setObjectName('sidebar')
        sidebar.setFixedWidth(222)
        nav = QVBoxLayout(sidebar)
        nav.setContentsMargins(22, 32, 22, 24)
        nav.setSpacing(10)
        nav.addWidget(label('ReViveX', 'brand'))
        nav.addWidget(label('R A N S O M', 'muted'))
        nav.addSpacing(36)
        nav.addWidget(self.tr_label('workspace', 'eyebrow'))
        nav.addSpacing(8)
        self.nav_buttons = []
        for index, key in enumerate(('recover', 'results', 'help', 'about')):
            button = self.tr_button(key)
            button.setObjectName('nav')
            button.setCheckable(True)
            button.clicked.connect(lambda checked=False, i=index: self.navigate(i))
            nav.addWidget(button)
            self.nav_buttons.append(button)
        nav.addStretch()
        nav.addWidget(label(f'v{info.VERSION}', 'muted'))
        self.language_box = QComboBox()
        self.language_box.addItems(['English', '简体中文'])
        self.language_box.setCurrentIndex(1 if self.language == 'zh' else 0)
        self.language_box.currentIndexChanged.connect(lambda i: self.set_language('zh' if i else 'en'))
        self.language_box.setAccessibleName('Language / 语言')
        nav.addWidget(self.language_box)
        self.theme_box = QComboBox()
        self.theme_box.addItems(['Light', 'Dark'])
        self.theme_box.currentIndexChanged.connect(lambda i: self.set_dark(bool(i)))
        nav.addWidget(self.theme_box)
        root_layout.addWidget(sidebar)
        self.pages = QStackedWidget()
        root_layout.addWidget(self.pages, 1)
        self.build_recovery()
        self.build_results()
        self.build_help()
        self.build_about()
        self.timer = QTimer(self)
        self.timer.setInterval(150)
        self.timer.timeout.connect(self.poll_job)
        self.auto_timer = QTimer(self)
        self.auto_timer.setInterval(750)
        self.auto_timer.timeout.connect(self.poll_auto_progress)
        self.auto_progress = None
        self.search_timer = QTimer(self)
        self.search_timer.setSingleShot(True)
        self.search_timer.setInterval(220)
        self.search_timer.timeout.connect(self.reset_results)
        self.search.textChanged.connect(lambda: self.search_timer.start())
        self.set_language(self.language)
        self.navigate(0)
        self.set_dark(initial_dark)
        screen = self.screen()
        available = screen.availableGeometry() if screen else None
        self.resize(min(1280, available.width() - 24) if available else 1280,
                    min(820, available.height() - 48) if available else 760)
        self.adapt_layout()

    def t(self, key):
        return TEXT[self.language].get(key, key)
    def tr_label(self, key, role='', wrap=False):
        widget = label(self.t(key), role, wrap)
        self._texts.append((widget, key))
        return widget
    def tr_button(self, key):
        widget = QPushButton(self.t(key).replace('&', '&&'))
        self._texts.append((widget, key))
        return widget
    def line(self, key=None):
        widget = QLineEdit()
        if key:
            widget.setPlaceholderText(self.t(key))
            self._placeholders.append((widget, key))
        return widget
    def page(self):
        page = QWidget()
        page.setObjectName('page')
        layout = QVBoxLayout(page)
        layout.setContentsMargins(34, 30, 34, 28)
        layout.setSpacing(18)
        self.pages.addWidget(page)
        return page, layout
    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'table'):
            self.adapt_layout()

    def adapt_layout(self):
        # Geometry is in logical pixels; Qt already applies system display scale.
        compact = self.height() < 820 or self.width() < 1200
        self.sidebar.setFixedWidth(174 if compact else 206)
        if compact != self._compact:
            self._compact = compact
            self.setStyleSheet(stylesheet(self.dark, compact=compact))
        for index in range(self.pages.count()):
            page = self.pages.widget(index)
            page.layout().setContentsMargins(*((16, 12, 16, 12) if compact else (28, 22, 28, 22)))
            page.layout().setSpacing(8 if compact else 14)
            for frame in page.findChildren(QFrame):
                if frame.objectName() == 'card' and frame.layout():
                    frame.layout().setContentsMargins(*((12, 10, 12, 10) if compact else (20, 18, 20, 18)))
                    frame.layout().setSpacing(7 if compact else 12)

    def heading(self, layout, title, subtitle=None):
        layout.addWidget(self.tr_label(title, 'title', True))
        if subtitle:
            layout.addWidget(self.tr_label(subtitle, 'muted', True))
    def file_row(self, layout, field, directory=False):
        row = QHBoxLayout()
        row.addWidget(field, 1)
        button = self.tr_button('browse')
        button.clicked.connect(lambda: self.choose_path(field, directory))
        row.addWidget(button)
        layout.addLayout(row)
    def choose_path(self, field, directory=False):
        path = QFileDialog.getExistingDirectory(self, self.t('browse')) if directory else QFileDialog.getOpenFileName(self, self.t('browse'))[0]
        if path:
            field.setText(path)

    def build_recovery(self):
        _, layout = self.page()
        layout.addWidget(self.tr_label('eyebrow', 'eyebrow'))
        self.heading(layout, 'title', 'subtitle')
        source_card, source_layout = card()
        source_layout.addWidget(self.tr_label('source', 'section'))
        source_layout.addWidget(self.tr_label('source_hint', 'muted', True))
        self.source = self.line('source_placeholder')
        self.file_row(source_layout, self.source)
        self.output_label = self.tr_label('output')
        source_layout.addWidget(self.output_label)
        self.output = self.line('output_placeholder')
        self.file_row(source_layout, self.output, True)
        self.workdir_panel = QWidget()
        workdir_layout = QVBoxLayout(self.workdir_panel)
        workdir_layout.setContentsMargins(0, 0, 0, 0)
        self.workdir = self.line('workdir_placeholder')
        self.workdir.setAccessibleName(self.t('workdir_placeholder'))
        self.file_row(workdir_layout, self.workdir, True)
        source_layout.addWidget(self.workdir_panel)
        self.staging_note = label('', 'muted', True)
        source_layout.addWidget(self.staging_note)
        source_layout.addStretch()
        cards = QHBoxLayout()
        cards.setSpacing(12)
        cards.addWidget(source_card, 1)
        method_card, method_layout = card()
        method_layout.addWidget(self.tr_label('method', 'section'))
        self.method = QComboBox()
        for action in ACTIONS:
            self.method.addItem(self.t(action), action)
        self.method.currentIndexChanged.connect(self.method_changed)
        method_layout.addWidget(self.method)
        self.method_description = label('', 'muted', True)
        method_layout.addWidget(self.method_description)
        self.partial_bat = QCheckBox()
        self.partial_bat.setChecked(False)
        method_layout.addWidget(self.partial_bat)
        self.pair_panel = QWidget()
        pair_layout = QVBoxLayout(self.pair_panel)
        pair_layout.setContentsMargins(0, 0, 0, 0)
        pair_layout.addWidget(self.tr_label('original'))
        self.original = self.line()
        self.file_row(pair_layout, self.original)
        pair_layout.addWidget(self.tr_label('encrypted'))
        self.encrypted = self.line()
        self.file_row(pair_layout, self.encrypted)
        method_layout.addWidget(self.pair_panel)
        self.member_panel = QWidget()
        member_layout = QVBoxLayout(self.member_panel)
        member_layout.setContentsMargins(0, 0, 0, 0)
        member_layout.addWidget(self.tr_label('member'))
        self.member = self.line()
        self.member.setPlaceholderText('folder/archive.zip')
        member_layout.addWidget(self.member)
        method_layout.addWidget(self.member_panel)
        self.limit_panel = QWidget()
        limits = QGridLayout(self.limit_panel)
        limits.setContentsMargins(0, 4, 0, 0)
        limits.addWidget(self.tr_label('file_limit', 'muted'), 0, 0)
        limits.addWidget(self.tr_label('total_limit', 'muted'), 0, 1)
        self.max_file = QSpinBox()
        self.max_file.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.max_file.setRange(1, 65536)
        self.max_file.setValue(128)
        self.max_total = QSpinBox()
        self.max_total.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.max_total.setRange(1, 1048576)
        self.max_total.setValue(1024)
        limits.addWidget(self.max_file, 1, 0)
        limits.addWidget(self.max_total, 1, 1)
        method_layout.addWidget(self.limit_panel)
        method_layout.addStretch()
        cards.addWidget(method_card, 1)
        layout.addLayout(cards, 1)
        layout.addWidget(self.tr_label('warning', 'muted', True))
        self.status = self.tr_label('ready', 'muted', True)
        layout.addWidget(self.status)
        self.auto_panel = QWidget()
        auto_layout = QVBoxLayout(self.auto_panel)
        auto_layout.setContentsMargins(0, 0, 0, 0)
        auto_layout.setSpacing(2)
        self.auto_stage_label = label('', 'section')
        self.auto_bytes_label = label('', 'muted')
        self.auto_counts_label = label('', 'muted')
        for widget in (self.auto_stage_label, self.auto_bytes_label, self.auto_counts_label):
            widget.setWordWrap(True)
            auto_layout.addWidget(widget)
        self.auto_panel.hide()
        layout.addWidget(self.auto_panel)
        self.progress = QProgressBar()
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        buttons = QHBoxLayout()
        buttons.addStretch()
        self.cancel_button = self.tr_button('cancel')
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self.cancel_job)
        buttons.addWidget(self.cancel_button)
        self.run_button = self.tr_button('run')
        self.run_button.setObjectName('primary')
        self.run_button.clicked.connect(self.start_scan)
        buttons.addWidget(self.run_button)
        layout.addLayout(buttons)
        self.input_panels = [source_card, method_card]

    def build_results(self):
        _, layout = self.page()
        self.heading(layout, 'results_title', 'results_sub')
        self.result_notice = label('', 'badge', True)
        self.result_notice.hide()
        notice_row = QHBoxLayout()
        notice_row.addWidget(self.result_notice, 1)
        self.result_cancel = self.tr_button('cancel')
        self.result_cancel.clicked.connect(self.cancel_job)
        self.result_cancel.hide()
        notice_row.addWidget(self.result_cancel)
        layout.addLayout(notice_row)
        toolbar = QHBoxLayout()
        self.search = self.line('search')
        toolbar.addWidget(self.search, 1)
        self.status_filter = QComboBox()
        self.status_filter.addItem(self.t('all'), None)
        self.status_filter.currentIndexChanged.connect(self.reset_results)
        toolbar.addWidget(self.status_filter)
        self.view_mode = QComboBox()
        self.view_mode.addItems(['Folders', 'File types', 'All files'])
        self.view_mode.currentIndexChanged.connect(self.view_changed)
        toolbar.addWidget(self.view_mode)
        layout.addLayout(toolbar)
        splitter = QSplitter()
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setItemDelegate(SelectionDelegate(self, self.tree))
        self.tree.setMinimumWidth(110)
        self.tree.itemSelectionChanged.connect(self.tree_changed)
        self.tree.itemChanged.connect(self.folder_checked)
        self.tree.itemExpanded.connect(self.expand_folder)
        self.tree.itemClicked.connect(self.tree_clicked)
        splitter.addWidget(self.tree)
        self.table = QTableWidget(0, 5)
        self.table.setItemDelegateForColumn(0, SelectionDelegate(self, self.table))
        self.table.setMinimumHeight(80)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(43)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setMinimumSectionSize(35)
        self.table.setColumnWidth(0, 230)
        self.table.setColumnWidth(3, 230)
        self.table.setColumnWidth(1, 115)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(4, 145)
        self.table.itemChanged.connect(self.row_checked)
        self.table.itemSelectionChanged.connect(self.show_row_detail)
        splitter.addWidget(self.table)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([205, 700])
        layout.addWidget(splitter, 1)
        self.result_caption = self.tr_label('empty', 'muted', True)
        layout.addWidget(self.result_caption)
        controls = QGridLayout()
        self.select_all = QPushButton()
        self.select_all.clicked.connect(self.select_all_available)
        self.clear_selection = QPushButton()
        self.clear_selection.clicked.connect(self.clear_all_selection)
        self.select_matches = QPushButton()
        self.select_matches.clicked.connect(lambda: self.select_filtered(True))
        self.open_workspace_button = QPushButton()
        self.open_workspace_button.clicked.connect(self.choose_workspace)
        self.resume_button = QPushButton()
        self.resume_button.clicked.connect(self.resume_scan)
        self.previous = QPushButton('‹')
        self.previous.setAccessibleName('Previous page')
        self.previous.clicked.connect(lambda: self.turn_page(-1))
        self.next = QPushButton('›')
        self.next.setAccessibleName('Next page')
        self.next.clicked.connect(lambda: self.turn_page(1))
        self.export_button = QPushButton()
        self.export_button.setObjectName('primary')
        self.export_button.clicked.connect(self.export_selected)
        for index, button in enumerate((self.select_all, self.select_matches, self.clear_selection,
                                        self.open_workspace_button, self.resume_button, self.export_button)):
            controls.addWidget(button, index // 3, index % 3)
            controls.setColumnStretch(index % 3, 1)
        paging = QHBoxLayout()
        paging.addWidget(self.previous)
        paging.addWidget(self.next)
        controls.addLayout(paging, 0, 3, 2, 1)
        layout.addLayout(controls)
        verification = QHBoxLayout()
        verification.addWidget(self.tr_label('not_authentic', 'muted', True), 1)
        self.verify_button = self.tr_button('verify')
        self.verify_button.setToolTip('Verify scan workspace manifests; selected export already checks copied bytes.')
        self.verify_button.clicked.connect(self.start_verify)
        verification.addWidget(self.verify_button)
        layout.addLayout(verification)
        self.details_toggle = self.tr_button('log')
        self.details_toggle.setCheckable(True)
        layout.addWidget(self.details_toggle, 0, Qt.AlignmentFlag.AlignLeft)
        self.detail_tabs = QTabWidget()
        self.detail_tabs.setMinimumHeight(80)
        self.detail_tabs.setMaximumHeight(125)
        self.details = QTextEdit()
        self.row_details = QTextEdit()
        self.export_details = QTextEdit()
        for editor, title in ((self.details, 'Run summary'), (self.row_details, 'Record details'), (self.export_details, 'Export report')):
            editor.setReadOnly(True)
            self.detail_tabs.addTab(editor, title)
        layout.addWidget(self.detail_tabs)
        self.detail_tabs.hide()
        self.details_toggle.toggled.connect(self.detail_tabs.setVisible)
        self.result_controls = [self.select_all, self.select_matches, self.clear_selection, self.open_workspace_button, self.resume_button, self.export_button, self.verify_button]
        for control in (self.select_all, self.clear_selection, self.export_button, self.previous, self.next):
            control.setEnabled(False)

    def build_help(self):
        _, layout = self.page()
        self.heading(layout, 'help_title')
        frame, body = card()
        body.addWidget(self.tr_label('help_body', '', True))
        body.addSpacing(12)
        body.addWidget(self.tr_label('docs', 'section'))
        self.doc_location = label('', 'muted', True)
        self.doc_location.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        body.addWidget(self.doc_location)
        documents = QHBoxLayout()
        for name in ('README.md', 'README.en.md', 'LICENSE', 'NOTICE'):
            button = QPushButton(name)
            button.clicked.connect(lambda checked=False, n=name: self.show_document(n))
            documents.addWidget(button)
        body.addLayout(documents)
        layout.addWidget(frame)
        layout.addStretch()

    def show_document(self, name):
        # Only fixed, packaged documentation may be displayed. Never recovery output.
        if name not in ('README.md', 'README.en.md', 'LICENSE', 'NOTICE'):
            return
        root = self.documentation_root()
        candidates = [root / name, root / 'docs' / name]
        document = next((p for p in candidates if p.is_file()), None)
        if document is None:
            self.alert(('未找到随附文档：' if self.language == 'zh' else 'Packaged document not found: ') + name)
            return
        dialog = QDialog(self)
        dialog.setWindowTitle(name)
        dialog.resize(780, 600)
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(document.read_text(encoding='utf-8', errors='replace'))
        layout.addWidget(text)
        close = QPushButton('关闭' if self.language == 'zh' else 'Close')
        close.clicked.connect(dialog.accept)
        layout.addWidget(close)
        dialog.exec()

    def build_about(self):
        _, layout = self.page()
        layout.addWidget(label('ReViveX Ransom', 'eyebrow'))
        self.heading(layout, 'about_title', 'about_body')
        frame, body = card()
        body.addWidget(label(f'{info.NAME}  {info.VERSION}', 'section'))
        for key, value in [('author', info.AUTHOR), ('contact', info.EMAIL), ('website', info.WEBSITE), ('license', info.LICENSE)]:
            body.addWidget(self.tr_label(key, 'muted'))
            value_label = label(value)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            body.addWidget(value_label)
        body.addWidget(label('Qt / PySide6 · LGPL-3.0\n' + info.COPYRIGHT, 'muted', True))
        layout.addWidget(frame)
        layout.addWidget(self.tr_label('warning', 'muted', True))
        layout.addStretch()

    def set_language(self, language):
        self.language = language
        if self.settings:
            self.settings.setValue('language', language)
        self.language_box.blockSignals(True)
        self.language_box.setCurrentIndex(1 if language == 'zh' else 0)
        self.language_box.blockSignals(False)
        for widget, key in self._texts:
            widget.setText(self.t(key).replace('&', '&&') if isinstance(widget, QPushButton) else self.t(key))
        for widget, key in self._placeholders:
            widget.setPlaceholderText(self.t(key))
        for index, action in enumerate(ACTIONS):
            self.method.setItemText(index, self.t(action))
        self.status_filter.setItemText(0, self.t('all'))
        if self.catalog:
            counts = {item['status']: item['count'] for item in self.catalog.statuses()}
            for i in range(1, self.status_filter.count()):
                value = self.status_filter.itemData(i)
                self.status_filter.setItemText(i, f'{self.display_status(value)} ({counts.get(value, 0)})')
        self.theme_box.setItemText(0, self.t('light'))
        self.theme_box.setItemText(1, self.t('dark'))
        self.theme_box.setAccessibleName(self.t('theme'))
        self.table.setHorizontalHeaderLabels([self.t(k) for k in ('name', 'state', 'size', 'path', 'detail')])
        zh = language == 'zh'
        for i, value in enumerate(['目录', '文件类型', '全部文件'] if zh else ['Folders', 'File types', 'All files']):
            self.view_mode.setItemText(i, value)
        self.output_label.setText('临时提取工作区' if zh else 'Temporary extraction workspace')
        self.staging_note.setText('扫描会将可恢复数据提取到新的临时任务目录，占用存储空间；之后可浏览、勾选并仅导出所选文件。请使用健康的独立存储。' if zh else 'Scanning extracts salvageable data into a new temporary run folder and uses storage space. Then browse, select and export only the files you choose. Use healthy separate storage.')
        self.select_all.setText('全选可导出项' if zh else 'Select all available')
        self.select_matches.setText('选择筛选结果' if zh else 'Select filtered')
        self.open_workspace_button.setText('打开已有任务' if zh else 'Open workspace')
        self.resume_button.setText('继续上次任务' if zh else 'Continue run')
        self.partial_bat.setText('尝试部分 BAT 映射（高级）' if zh else 'Try partial BAT mappings (advanced)')
        self.partial_bat.setToolTip('仍须有效关键元数据；无效或冲突的数据块标记为不可读取。不保证内容完整。' if zh else 'Critical metadata must still validate. Invalid or conflicting blocks remain unreadable. This does not establish content integrity.')
        for index, title in enumerate(('任务摘要', '记录详情', '导出报告') if zh else ('Run summary', 'Record details', 'Export report')):
            self.detail_tabs.setTabText(index, title)
        self.clear_selection.setText('清空全部选择' if zh else 'Clear all selection')
        self.export_button.setText('导出所选文件' if zh else 'Export selected')
        self.doc_location.setText(str(self.documentation_root()) + '\nREADME.md · README.en.md · LICENSE · NOTICE')
        self.method_changed()
        if self.auto_panel.isVisibleTo(self):
            self.render_auto_progress()
        self.refresh_results()

    def documentation_root(self):
        return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent.parent))
    def set_dark(self, dark):
        self.dark = dark
        if self.settings:
            self.settings.setValue('dark', dark)
        self.theme_box.blockSignals(True)
        self.theme_box.setCurrentIndex(int(dark))
        self.theme_box.blockSignals(False)
        self.setStyleSheet(stylesheet(dark, compact=bool(self._compact)))
    def navigate(self, index):
        self.pages.setCurrentIndex(index)
        for i, button in enumerate(self.nav_buttons):
            button.setChecked(i == index)
    def method_changed(self):
        action = self.method.currentData()
        self.method_description.setText(self.t(action + '_desc'))
        self.partial_bat.setVisible(action == 'logical_ntfs')
        self.pair_panel.setVisible(action == 'pairs')
        self.member_panel.setVisible(action == 'inner')
        self.limit_panel.setVisible(action in ('auto', 'zip', 'carve', 'resident'))
        self.workdir_panel.setVisible(action == 'auto')
        zh = self.language == 'zh'
        self.output_label.setText(self.t('output_auto') if action == 'auto' else ('临时提取工作区' if zh else 'Temporary extraction workspace'))
        if action == 'auto':
            self.staging_note.setText(self.t('auto_note'))
        elif action == 'logical_ntfs':
            self.staging_note.setText('仅索引元数据，不提取全部文件；所选文件在导出时从源镜像读取。请保持源镜像不变。' if self.language == 'zh' else 'Metadata-only scan: files are read from the source only when you export your selection. Keep the source image unchanged.')
        else:
            self.staging_note.setText('扫描会提取数据并占用临时存储；随后仅导出所选文件。' if self.language == 'zh' else 'This scan extracts staged data and uses temporary storage; then export only your selection.')
        self.max_file.setEnabled(action != 'resident')
        self.run_button.setText(self.t('run_auto') if action == 'auto' else self.t('analyze') if action in ('probe', 'pairs') else ('扫描并建立索引' if self.language == 'zh' else 'Scan && build index'))
    def busy(self):
        return bool(self._operation_active or (self.runner and self.runner.running) or (self.worker and self.worker.isRunning()))
    def set_busy(self, busy):
        self._operation_active = busy
        self.run_button.setEnabled(not busy)
        for panel in self.input_panels:
            panel.setEnabled(not busy)
        for control in self.result_controls:
            control.setEnabled(not busy)
        self.cancel_button.setEnabled(busy)
        self.result_cancel.setVisible(busy)
        self.result_cancel.setEnabled(busy)
        self.table.setEnabled(not busy)
        self.tree.setEnabled(not busy)
        self.progress.setRange(0, 0 if busy else 1)
        self.progress.setValue(0)
    def set_status(self, text):
        self.status.setText(text)
        self.result_notice.setText(text)
        self.result_notice.show()
    def alert(self, message):
        QMessageBox.warning(self, self.t('error'), message)
    def fresh_output(self, parent, prefix='revivex-scan'):
        return str(Path(parent) / f'{prefix}-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}')
    def start_scan(self):
        if self.busy():
            return
        source = Path(self.source.text().strip())
        if not source.is_file():
            self.alert(self.t('source_missing')); return
        parent = Path(self.output.text().strip())
        if not self.output.text().strip() or not parent.is_dir():
            self.alert(self.t('output_missing')); return
        action = self.method.currentData()
        options = {}
        if action == 'logical_ntfs' and self.partial_bat.isChecked():
            options['allow_partial_bat'] = True
        if action in ('auto', 'zip', 'carve'):
            options.update(max_file_mib=self.max_file.value(), max_total_mib=self.max_total.value())
        if action == 'auto' and self.workdir.text().strip():
            workdir = Path(self.workdir.text().strip())
            if not workdir.is_dir():
                self.alert(self.t('workdir_missing')); return
            options['work_dir'] = str(workdir)
        if action == 'zip':
            options.update(memory_map=True, preserve_duplicates=True)
        if action == 'resident':
            options['max_output_bytes'] = self.max_total.value() * 1024 * 1024
        if action == 'pairs':
            if not Path(self.original.text()).is_file() or not Path(self.encrypted.text()).is_file():
                self.alert(self.t('pair_missing')); return
            options['pairs'] = [[self.original.text(), self.encrypted.text()]]
        if action == 'inner':
            if not self.member.text().strip():
                self.alert(self.t('member_missing')); return
            options['outer_member'] = self.member.text().strip()
        self.begin_job('ntfs' if action == 'resident' else 'logical_index' if action == 'logical_ntfs' else action, str(source), self.fresh_output(parent), options)
    def begin_job(self, tool, source, output, options):
        from revivex_jobs import JobRunner, JobSpec
        try:
            self.runner = JobRunner()
            self.runner.start(JobSpec(tool=tool, source=source, output=output, options=options))
        except Exception as exc:
            self.runner = None
            self.alert(str(exc)); return
        self.last_output = output
        self.job_tool = tool
        self.job_source = source
        self.set_status(self.t('running'))
        self.details.clear()
        self.row_details.clear()
        self.export_details.clear()
        self.run_summary = {}
        self.set_busy(True)
        self.timer.start()
        if tool == 'auto':
            self.start_auto_progress(output)
    def start_auto_progress(self, output):
        self.auto_progress = None
        self.auto_progress_path = Path(output) / 'progress.json'
        self.auto_panel.show()
        self.render_auto_progress()
        self.auto_timer.start()
    def stop_auto_progress(self):
        self.auto_timer.stop()
        self.auto_panel.hide()
        self.auto_progress = None
        self.progress.setRange(0, 0 if self.busy() else 1)
        self.progress.setValue(0)
    def poll_auto_progress(self):
        try:
            with open(self.auto_progress_path, 'rb') as handle:
                data = json.loads(handle.read(1 << 16).decode('utf-8'))
            if isinstance(data, dict):
                self.auto_progress = data
        except (OSError, ValueError):
            pass  # transiently missing or mid-rewrite: keep last good value
        self.render_auto_progress()
    @staticmethod
    def _num(value):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else None
    @staticmethod
    def format_bytes(value):
        value = float(value)
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
            if value < 1024 or unit == 'TiB':
                return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
            value /= 1024
    @staticmethod
    def format_duration(seconds):
        seconds = int(seconds)
        h, rest = divmod(seconds, 3600)
        m, s = divmod(rest, 60)
        return f'{h}:{m:02d}:{s:02d}' if h else f'{m}:{s:02d}'
    def render_auto_progress(self):
        data = self.auto_progress
        if not data:
            self.auto_stage_label.setText(self.t('auto_prep'))
            self.auto_bytes_label.setText('')
            self.auto_counts_label.setText('')
            self.progress.setRange(0, 0)
            return
        stage = str(data.get('stage', ''))
        index = data.get('stage_index')
        name = self.t('stage_' + stage) if ('stage_' + stage) in TEXT[self.language] else stage
        count = data.get('stage_count')
        if isinstance(count, int) and not isinstance(count, bool) and count > 0:
            self.auto_stage_label.setText(self.t('auto_stage').format(i=index if isinstance(index, int) else '?', n=count, name=name))
        else:
            self.auto_stage_label.setText(self.t('auto_stage_open').format(i=index if isinstance(index, int) else '?', name=name))
        done = self._num(data.get('scanned_bytes')) or 0
        plan = self._num(data.get('planned_bytes'))
        speed = self._num(data.get('bytes_per_second'))
        if data.get('unit') == 'items':
            if plan:
                lines = [self.t('auto_items').format(done=int(done), plan=int(plan))]
                self.progress.setRange(0, 1000)
                self.progress.setValue(min(1000, int(done * 1000 / plan)))
            else:
                lines = [self.t('auto_items_unknown').format(done=int(done))]
                self.progress.setRange(0, 0)
            speed = None
        elif plan:
            lines = [self.t('auto_bytes').format(done=self.format_bytes(done), plan=self.format_bytes(plan))]
            self.progress.setRange(0, 1000)
            self.progress.setValue(min(1000, int(done * 1000 / plan)))
        else:
            lines = [self.t('auto_bytes_unknown').format(done=self.format_bytes(done))]
            self.progress.setRange(0, 0)
        if speed:
            lines.append(self.t('auto_speed').format(speed=self.format_bytes(speed)))
            if plan and plan > done:
                lines.append(self.t('auto_eta').format(eta=self.format_duration((plan - done) / speed)))
        self.auto_bytes_label.setText(' · '.join(lines))
        counts = [self._num(data.get(k)) or 0 for k in ('verified_files', 'candidates', 'failed')]
        text = self.t('auto_counts').format(v=int(counts[0]), c=int(counts[1]), f=int(counts[2]))
        extra = self._num(data.get('extra_read_bytes'))
        if extra:
            text += ' · ' + self.t('auto_extra').format(x=self.format_bytes(extra))
        self.auto_counts_label.setText(text)
    def poll_job(self):
        if not self.runner:
            return
        try:
            result = self.runner.poll()
        except Exception as exc:
            self.timer.stop()
            self.stop_auto_progress()
            self.set_busy(False)
            self.alert(str(exc))
            return
        if result is None:
            return
        self.timer.stop()
        self.stop_auto_progress()
        self.runner = None
        self.set_status(self.t('stopped') if result.status == 'cancelled' else self.t('complete') if result.status == 'completed' else self.t('failed'))
        self.run_summary = result.summary
        summary = json.dumps(result.summary, ensure_ascii=False, indent=2, default=str)
        self.details.setPlainText(summary + '\n' + str(result.error or '') + '\n' + str(result.log or '')[-12000:])
        if result.summary.get('catalog_path') and self.job_tool != 'verify':
            from revivex_catalog import RecoveryCatalog
            self.catalog_ready(RecoveryCatalog(result.summary['catalog_path']))
        elif result.rows and self.job_tool != 'verify':
            self.ingest_rows(result.rows, self.last_output, self.job_source)
        else:
            self.set_busy(False)
            self.navigate(1)
            if not result.rows:
                self.result_caption.setText(self.t('no_records'))
            self.finish_close()
    def ingest_rows(self, rows, output, source):
        from revivex_catalog import RecoveryCatalog
        catalog_path = Path(output) / 'selection.sqlite'
        source_id = uuid.uuid4().hex
        def work():
            catalog = RecoveryCatalog(catalog_path)
            catalog.ingest(source_id, rows, source_label=Path(source).name, source_path=source)
            return catalog
        self.worker = TaskThread(work, self)
        self.worker.result.connect(self.catalog_ready)
        self.worker.finished.connect(self.refresh_results)
        self.worker.failed.connect(self.worker_failed)
        self.worker.start()
    def catalog_ready(self, catalog):
        if self.catalog is not None and self.catalog is not catalog:
            self.catalog.close()
        self.catalog = catalog
        saved_summary = catalog.run_summary()
        self.run_summary = saved_summary
        if saved_summary:
            self.details.setPlainText(json.dumps(saved_summary, ensure_ascii=False, indent=2))
        self.status_filter.blockSignals(True)
        self.status_filter.clear()
        self.status_filter.addItem(self.t('all'), None)
        for item in catalog.statuses():
            self.status_filter.addItem(f"{self.display_status(item['status'])} ({item['count']})", item['status'])
        self.status_filter.blockSignals(False)
        self.offset = 0
        self.filter_kind = self.filter_value = None
        self.set_busy(False)
        self.rebuild_tree()
        self.refresh_results()
        self.navigate(1)
        self.finish_close()
    def worker_failed(self, error):
        self.set_busy(False)
        self.details.append(error)
        self.set_status(self.t('failed'))
        self.finish_close()
    def cancel_job(self):
        if self.runner:
            self.runner.cancel()
        elif hasattr(self, 'export_cancel'):
            self.export_cancel.set()
        self.cancel_button.setEnabled(False)
        self.result_cancel.setEnabled(False)
        self.set_status(self.t('canceling'))
    def start_verify(self):
        if self.busy():
            return
        root = QFileDialog.getExistingDirectory(self, self.t('choose_verify'), self.last_output)
        if root:
            # Verification reads an existing directory; reports go to a fresh sibling.
            self.begin_job('verify', root, self.fresh_output(Path(root).parent, 'revivex-verify'), {})
    def filters(self):
        filters = {'search': self.search.text().strip()}
        if self.status_filter.currentData():
            filters['status'] = self.status_filter.currentData()
        if self.filter_kind == 'group':
            filters['group'] = self.filter_value
        if self.filter_kind == 'folder':
            filters['folder'] = self.filter_value
        if self.filter_source:
            filters['source_id'] = self.filter_source
        return filters
    def reset_results(self):
        self.offset = 0
        self.refresh_results()
    def view_changed(self):
        self.filter_kind = self.filter_value = self.filter_source = None
        self.offset = 0
        self.rebuild_tree()
        self.refresh_results()
    def rebuild_tree(self):
        self._refreshing = True
        self.tree.clear()
        self.tree.setVisible(self.view_mode.currentIndex() != 2)
        if self.catalog:
            if self.view_mode.currentIndex() == 1:
                for group in self.catalog.groups():
                    item = QTreeWidgetItem([f"{group['group']}  ({group['count']})"])
                    item.setData(0, Qt.ItemDataRole.UserRole, ('group', group['group']))
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(0, Qt.CheckState.Unchecked)
                    self.tree.addTopLevelItem(item)
            else:
                for source in self.catalog.sources():
                    item = QTreeWidgetItem([source['label']])
                    item.setData(0, Qt.ItemDataRole.UserRole, ('folder', ''))
                    item.setData(0, Qt.ItemDataRole.UserRole + 1, source['id'])
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(0, Qt.CheckState.Unchecked)
                    self.tree.addTopLevelItem(item)
                    self.load_folders(item, source['id'], '', 0)
                    item.setExpanded(True)
        self._refreshing = False
    def load_folders(self, parent, source_id, path, offset):
        folders = self.catalog.folders(source_id=source_id, parent=path, offset=offset, limit=100)
        for folder in folders:
            child = QTreeWidgetItem([self.display_path(folder['path'].rsplit('/', 1)[-1]) + f"  ({folder['count']})"])
            child.setToolTip(0, folder['path'])
            child.setData(0, Qt.ItemDataRole.UserRole, ('folder', folder['path']))
            child.setData(0, Qt.ItemDataRole.UserRole + 1, source_id)
            child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            child.setCheckState(0, Qt.CheckState.Unchecked)
            child.addChild(QTreeWidgetItem(['…']))
            parent.addChild(child)
        if len(folders) == 100:
            more = QTreeWidgetItem(['加载更多…' if self.language == 'zh' else 'Load more…'])
            more.setData(0, Qt.ItemDataRole.UserRole, ('more', (source_id, path, offset + 100)))
            parent.addChild(more)
    def expand_folder(self, item):
        if not self.catalog or self.busy():
            return
        if item.childCount() == 1 and item.child(0).data(0, Qt.ItemDataRole.UserRole) is None:
            self._refreshing = True
            item.takeChild(0)
            kind, path = item.data(0, Qt.ItemDataRole.UserRole)
            self.load_folders(item, item.data(0, Qt.ItemDataRole.UserRole + 1), path, 0)
            self.sync_tree_checks()
            self._refreshing = False
    def tree_clicked(self, item, column):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if data and data[0] == 'more' and not self.busy():
            parent = item.parent()
            self._refreshing = True
            parent.takeChild(parent.indexOfChild(item))
            self.load_folders(parent, *data[1])
            self.sync_tree_checks()
            self._refreshing = False
    def tree_changed(self):
        selected = self.tree.selectedItems()
        if self._refreshing or not selected:
            return
        data = selected[0].data(0, Qt.ItemDataRole.UserRole)
        if not data or data[0] == 'more':
            return
        self.filter_kind, self.filter_value = data
        self.filter_source = selected[0].data(0, Qt.ItemDataRole.UserRole + 1)
        self.reset_results()
    def folder_checked(self, item, column):
        if self._refreshing or not self.catalog or self.busy():
            return
        kind, path = item.data(0, Qt.ItemDataRole.UserRole)
        if kind == 'folder':
            self.catalog.select_folder(item.data(0, Qt.ItemDataRole.UserRole + 1), path, item.checkState(0) == Qt.CheckState.Checked)
        elif kind == 'group':
            self.catalog.select_filtered(group=path, selected=item.checkState(0) == Qt.CheckState.Checked)
        self.refresh_results()
    def refresh_results(self):
        self._refreshing = True
        self.table.setRowCount(0)
        total = selected = 0
        rows = []
        if self.catalog:
            filters = self.filters()
            total = self.catalog.count(**filters)
            rows = self.catalog.query(**filters, offset=self.offset, limit=self.PAGE_SIZE)
            selected = self.catalog.selected_count()
        for row_number, row in enumerate(rows):
            self.table.insertRow(row_number)
            values = [row.get('name') or row.get('relative_path') or '—', self.display_status(row.get('status', 'unknown')), self.format_size(row.get('size')), self.display_path(row.get('relative_path') or self.t('unknown_path')), self.display_integrity(row.get('integrity', 'unknown'))]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                item.setToolTip(str(row.get('integrity', value)) if column == 4 else str(row.get('status', value)) if column == 1 else str(value))
                if column == 0:
                    item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable if row.get('eligible') else item.flags() & ~Qt.ItemFlag.ItemIsUserCheckable)
                    item.setCheckState(Qt.CheckState.Checked if row.get('selected') else Qt.CheckState.Unchecked)
                    item.setData(Qt.ItemDataRole.UserRole, row)
                self.table.setItem(row_number, column, item)
        self.previous.setEnabled(self.offset > 0)
        self.next.setEnabled(self.offset + len(rows) < total)
        if self.catalog:
            available = self.catalog.count(eligible_only=True)
            unavailable = self.catalog.count() - available
            self.result_caption.setText((f'{total:,} 个匹配项 · 可导出 {available:,} 项 · 不可导出 {unavailable:,} 项 · 已选 {selected:,} 项 · 原始总数未知 · 显示 {self.offset + 1 if rows else 0}–{self.offset + len(rows)}' if self.language == 'zh' else f'{total:,} matching records · {available:,} available · {unavailable:,} unavailable · {selected:,} selected · original total unknown · showing {self.offset + 1 if rows else 0}–{self.offset + len(rows)}'))
        self.export_button.setEnabled(selected > 0 and not self.busy())
        self.select_all.setEnabled(bool(self.catalog and self.catalog.count(eligible_only=True)) and not self.busy())
        self.clear_selection.setEnabled(selected > 0 and not self.busy())
        self.select_matches.setEnabled(total > 0 and not self.busy())
        self.open_workspace_button.setEnabled(not self.busy())
        self.resume_button.setEnabled(not self.busy() and bool(self.catalog) and self.can_resume())
        self.sync_tree_checks()
        self._refreshing = False
    def display_path(self, path):
        if self.language == 'zh':
            if path == 'Unknown path' or path.startswith('Unknown path/'):
                return '原始路径未知' + path[len('Unknown path'):]
            if path == 'Inferred path' or path.startswith('Inferred path/'):
                return '推断路径（未确认）' + path[len('Inferred path'):]
        return path
    def display_status(self, status):
        mapping = {'deleted_usable': ('已删除 · 可用', 'Deleted · usable'), 'deleted_needs_review': ('已删除 · 待确认', 'Deleted · needs review'), 'deleted_suspect_damaged': ('已删除 · 疑似损坏', 'Deleted · suspect damaged'), 'deleted_thumbnail_cache': ('已删除 · 缩略图缓存', 'Deleted · thumbnail cache'), 'usable': ('可用', 'Usable'), 'needs_review': ('待确认', 'Needs review'), 'suspect_damaged': ('疑似损坏', 'Suspect damaged'), 'thumbnail_cache': ('缩略图缓存', 'Thumbnail cache'), 'not_recovered': ('未恢复', 'Not recovered'), 'unavailable': ('不可用', 'Unavailable'), 'logical_candidate': ('已索引 · 尚未提取', 'Indexed · not yet recovered'), 'partial_unverified': ('部分输出 · 未验证', 'Partial output · unverified'), 'directory': ('目录', 'Directory'), 'unsupported': ('不支持', 'Unsupported'), 'unsupported_nonresident': ('非驻留流未恢复', 'Nonresident stream unavailable'), 'invalid_record': ('无效记录', 'Invalid record'), 'rejected': ('未恢复候选项', 'Rejected candidate'), 'output_limit': ('输出上限', 'Output limit'), 'unrecoverable': ('无法恢复', 'Unrecoverable'), 'recovered': ('已暂存', 'Staged'), 'staged': ('已暂存', 'Staged'), 'unverified': ('未验证', 'Unverified'), 'partial': ('部分数据', 'Partial'), 'failed': ('失败', 'Failed'), 'corrupt': ('损坏', 'Corrupt'), 'unknown': ('未知', 'Unknown')}
        return mapping.get(status, (status, status))[0 if self.language == 'zh' else 1]
    def display_integrity(self, integrity):
        if integrity.startswith('indexed:'):
            return '逻辑映射已验证 · 数据尚未读取' if self.language == 'zh' else 'Logical mapping validated · bytes not yet read'
        if integrity.startswith('verified:'):
            return '校验通过 · 暂存数据' if self.language == 'zh' else 'Staged bytes verified'
        if integrity.startswith('failed:'):
            return '校验失败' if self.language == 'zh' else 'Integrity check failed'
        return '未验证 · 内容完整性未知' if self.language == 'zh' else 'Unverified · completeness unknown'
    def sync_tree_checks(self):
        if not self.catalog:
            return
        def sync(item):
            data = item.data(0, Qt.ItemDataRole.UserRole)
            if data and data[0] in ('folder', 'group'):
                filters = {data[0]: data[1]}
                source = item.data(0, Qt.ItemDataRole.UserRole + 1)
                if source:
                    filters['source_id'] = source
                total = self.catalog.count(**filters, eligible_only=True)
                selected = self.catalog.count(**filters, selected_only=True)
                state = Qt.CheckState.Unchecked if not selected else Qt.CheckState.Checked if selected == total else Qt.CheckState.PartiallyChecked
                item.setCheckState(0, state)
            for index in range(item.childCount()):
                sync(item.child(index))
        for index in range(self.tree.topLevelItemCount()):
            sync(self.tree.topLevelItem(index))
    @staticmethod
    def format_size(value):
        if not isinstance(value, (int, float)):
            return '—'
        for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
            if value < 1024:
                return f'{value:.0f} {unit}' if unit == 'B' else f'{value:.1f} {unit}'
            value /= 1024
        return f'{value:.1f} PiB'
    def row_checked(self, item):
        if self._refreshing or item.column() != 0 or not self.catalog or self.busy():
            return
        row = item.data(Qt.ItemDataRole.UserRole)
        self.catalog.set_selected([row['id']], item.checkState() == Qt.CheckState.Checked)
        self.refresh_results()
    def show_row_detail(self):
        row = self.table.currentRow()
        if row >= 0 and self.table.item(row, 0):
            self.row_details.setPlainText(json.dumps(self.table.item(row, 0).data(Qt.ItemDataRole.UserRole), ensure_ascii=False, indent=2, default=str))
    def choose_workspace(self):
        if self.busy():
            return
        path = QFileDialog.getExistingDirectory(self, '打开已有任务' if self.language == 'zh' else 'Open recovery workspace')
        if path:
            self.open_workspace(path)
    def open_workspace(self, path):
        from revivex_jobs import reopen_workspace
        if self.busy():
            return
        self.set_busy(True)
        self.last_output = str(Path(path).parent if Path(path).is_file() else path)
        self.worker = TaskThread(lambda: reopen_workspace(path), self)
        self.worker.result.connect(self.catalog_ready)
        self.worker.finished.connect(self.refresh_results)
        self.worker.failed.connect(self.worker_failed)
        self.worker.start()
    def can_resume(self):
        summary = self.run_summary or {}
        manifests = summary.get('manifests', [])
        if summary.get('tool') == 'auto':
            return summary.get('scan_status') == 'cancelled' or any(
                m.get('status') not in ('completed', None) for m in manifests if m.get('schema') == 'revivex.auto-recovery')
        return summary.get('tool') == 'logical_index' and (summary.get('scan_status') == 'cancelled' or any(
            m.get('status') in ('running', 'interrupted') for m in manifests))
    def resume_auto(self):
        workspace = Path(self.catalog.db_path).absolute().parent
        request = json.loads((workspace / 'job_request.json').read_text(encoding='utf-8'))
        options = {k: v for k, v in request.get('options', {}).items() if k != 'resume'}
        options['resume'] = True
        self.begin_job('auto', request['source'], str(workspace), options)
    def resume_scan(self):
        if self.busy() or not self.catalog or not self.can_resume():
            return
        if self.run_summary.get('tool') == 'auto':
            try:
                self.resume_auto()
            except Exception as error:
                self.alert(str(error))
            return
        from revivex_scan_session import ScanSession
        try:
            workspace = Path(self.catalog.db_path).absolute().parent
            session_path = workspace / 'payload' / 'session.sqlite'
            with ScanSession(session_path) as session:
                source = session.identity['path']
                options = {'resume_session': str(session_path), 'source_format': session.options['source_format'], 'allow_partial_bat': session.options.get('allow_partial_bat', False)}
                if session.options.get('max_records'):
                    options['max_records'] = session.options['max_records']
            self.begin_job('logical_index', source, self.fresh_output(workspace.parent), options)
        except Exception as error:
            self.alert(str(error))
    def select_all_available(self):
        if self.catalog and not self.busy():
            self.catalog.select_filtered()
            self.refresh_results()
    def clear_all_selection(self):
        if self.catalog and not self.busy():
            self.catalog.select_filtered(False)
            self.refresh_results()
    def select_filtered(self, selected):
        if self.catalog and not self.busy():
            self.catalog.select_filtered(selected=selected, **self.filters())
            self.refresh_results()
    def turn_page(self, direction):
        self.offset = max(0, self.offset + direction * self.PAGE_SIZE)
        self.refresh_results()
    def export_selected(self):
        if not self.catalog or self.busy() or not self.catalog.selected_count():
            return
        parent = QFileDialog.getExistingDirectory(self, '导出到新目录' if self.language == 'zh' else 'Export into a new folder')
        if not parent:
            return
        import threading
        self.export_cancel = threading.Event()
        destination = self.fresh_output(parent, 'revivex-selected')
        self.set_busy(True)
        self.set_status(self.t('running'))
        self.worker = TaskThread(lambda: self.catalog.export_selected(destination, cancel_event=self.export_cancel), self)
        self.worker.result.connect(self.export_finished)
        self.worker.finished.connect(self.refresh_results)
        self.worker.failed.connect(self.worker_failed)
        self.worker.start()
    def export_finished(self, result):
        self.set_busy(False)
        self.export_details.setPlainText(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        self.details_toggle.setChecked(True)
        self.detail_tabs.setCurrentIndex(2)
        cancelled = bool(result.get('cancelled'))
        failed = int(result.get('failed', 0))
        copied = int(result.get('recovered', 0))
        directories = int(result.get('directories_created', 0))
        if self.language == 'zh':
            summary = f"{'已取消' if cancelled else '部分失败' if failed else '导出完成'} · 已复制并核验 {copied} 项 · 目录 {directories} 个 · 失败 {failed} 项"
        else:
            summary = f"{'Canceled' if cancelled else 'Completed with failures' if failed else 'Export complete'} · {copied} copied and verified · {directories} directories · {failed} failed"
        missing = result.get('scan_summary', {}).get('known_failed', 0)
        summary += (f' · 扫描中 {missing} 个候选项不可用 · 原始总数未知' if self.language == 'zh' else f' · {missing} scan candidates unavailable · original total unknown')
        self.set_status(summary)
        self.refresh_results()
        self.finish_close()
    def closeEvent(self, event):
        if self.busy():
            if self.close_pending or QMessageBox.question(self, self.t('close_title'), self.t('close_body'), QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
                self.close_pending = True
                self.cancel_job()
            event.ignore()
        else:
            self.timer.stop()
            self.auto_timer.stop()
            self.search_timer.stop()
            event.accept()
    def finish_close(self):
        if self.close_pending:
            QTimer.singleShot(200, self.close)
