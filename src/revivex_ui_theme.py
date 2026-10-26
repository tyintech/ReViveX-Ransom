"""A restrained, accessible desktop theme with native keyboard focus."""
def stylesheet(dark=False, compact=False):
    bg, panel, ink, muted, line, accent, soft = ('#101923','#17232f','#f0f5fb','#aab9c8','#304252','#75d4c0','#223e40') if dark else ('#f4f7fa','#ffffff','#172b3a','#5f7283','#dce5ec','#087e71','#e8f5f1')
    style = f'''
    QWidget {{ color: {ink}; font-size: 14px; }}
    QMainWindow, QStackedWidget, QScrollArea, QWidget#page {{ background: {bg}; }}
    QFrame#sidebar {{ background: {panel}; border-right: 1px solid {line}; }}
    QFrame#card {{ background: {panel}; border: 1px solid {line}; border-radius: 14px; }}
    QLabel {{ background: transparent; }}
    QLabel#title {{ font-size: 30px; font-weight: 650; }}
    QLabel#section {{ font-size: 18px; font-weight: 600; }}
    QLabel#eyebrow {{ color: {accent}; font-size: 11px; font-weight: 700; }}
    QLabel#muted {{ color: {muted}; }}
    QLabel#brand {{ font-size: 22px; font-weight: 700; }}
    QLabel#badge {{ color: {accent}; background: {soft}; border-radius: 9px; padding: 7px 10px; }}
    QPushButton {{ background: {panel}; border: 1px solid {line}; border-radius: 8px; padding: 10px 16px; font-weight: 550; }}
    QPushButton:hover {{ background: {soft}; border-color: {accent}; }}
    QPushButton:focus, QLineEdit:focus, QComboBox:focus {{ border: 2px solid {accent}; }}
    QPushButton:disabled {{ color: {muted}; background: {bg}; }}
    QPushButton#primary {{ background: {accent}; color: {'#102b29' if dark else '#ffffff'}; border: 0; padding: 12px 22px; }}
    QPushButton#nav {{ text-align: left; padding: 14px 16px; border: 0; background: transparent; }}
    QPushButton#nav:checked {{ background: {soft}; color: {accent}; }}
    QLineEdit, QComboBox, QSpinBox {{ background: {panel}; border: 1px solid {line}; border-radius: 8px; padding: 9px 11px; min-height: 20px; selection-background-color: {accent}; }}
    QComboBox::drop-down {{ border: 0; width: 28px; }}
    QComboBox QAbstractItemView {{ background: {panel}; selection-background-color: {soft}; color: {ink}; }}
    QTableWidget, QTreeWidget, QTextEdit {{ background: {panel}; alternate-background-color: {bg}; border: 1px solid {line}; border-radius: 8px; gridline-color: {line}; selection-background-color: {soft}; selection-color: {ink}; }}
    QTableWidget::item {{ padding: 7px; }}
    QHeaderView {{ background: {bg}; }}
    QTableCornerButton::section {{ background: {bg}; border: 0; }}
    QAbstractScrollArea::corner {{ background: {bg}; }}
    QHeaderView::section {{ background: {bg}; color: {muted}; border: 0; border-bottom: 1px solid {line}; padding: 10px; font-weight: 600; }}
    QProgressBar {{ border: 0; background: {line}; border-radius: 3px; height: 6px; max-height: 6px; }}
    QProgressBar::chunk {{ background: {accent}; border-radius: 3px; }}
    QToolTip {{ background: {panel}; color: {ink}; border: 1px solid {line}; padding: 6px; }}
    QScrollBar:horizontal {{ background: {bg}; height: 10px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {line}; min-width: 30px; border-radius: 5px; }}
    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; }}
    QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: {bg}; }}
    QTreeView::indicator, QTableView::indicator {{ width: 16px; height: 16px; }}
    QScrollBar:vertical {{ background: {bg}; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {line}; min-height: 30px; border-radius: 5px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    '''

    if compact:
        style += """
        QWidget { font-size: 12px; }
        QLabel#title { font-size: 23px; }
        QLabel#section { font-size: 15px; }
        QPushButton { padding: 6px 9px; }
        QPushButton#primary { padding: 7px 12px; }
        QPushButton#nav { padding: 10px 9px; }
        QLineEdit, QComboBox, QSpinBox { padding: 5px 7px; min-height: 18px; }
        QHeaderView::section { padding: 7px 4px; }
        QLabel#badge { padding: 5px 7px; }
        """
    return style
