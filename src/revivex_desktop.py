#!/usr/bin/env python3
"""ReViveX desktop entry point. Job dispatch happens before importing Qt."""
import sys

def main(argv=None):
    from revivex_jobs import dispatch_worker
    if dispatch_worker():
        return 0
    import os
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == '--diagnose':
        from diagnose_recovery_source import main as diagnose
        return diagnose(args[1:])
    if '--self-test' in args:
        os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
    from PySide6.QtWidgets import QApplication
    from PySide6.QtGui import QFont
    from revivex_ui import MainWindow
    app = QApplication.instance() or QApplication([sys.argv[0]])
    app.setApplicationName('ReViveX Ransom')
    app.setOrganizationName('ReViveX')
    font = QFont()
    font.setFamilies(['Segoe UI', 'Microsoft YaHei UI', 'PingFang SC', 'Noto Sans', 'Noto Sans CJK SC'])
    font.setPointSize(10)
    app.setFont(font)
    window = MainWindow(persist_settings='--self-test' not in args)
    window.show()
    if '--self-test' in args:
        app.processEvents()
        window.set_language('en')
        window.set_dark(True)
        window.navigate(1)
        app.processEvents()
        assert window.pages.count() == 4
        assert window.run_button.isEnabled()
        window.close()
        from revivex_jobs import self_test
        import json
        result = self_test()
        print('ReViveX desktop self-test: PASS ' + json.dumps(result, sort_keys=True))
        return 0
    return app.exec()

if __name__ == '__main__':
    raise SystemExit(main())
