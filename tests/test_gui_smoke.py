"""Smoke tests for the optional Qt desktop GUI."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from forensic_image_scanner.gui import create_application, main
from forensic_image_scanner.gui.main_window import MainWindow


def test_gui_entry_points_are_importable() -> None:
    assert callable(create_application)
    assert callable(main)


def test_main_window_initializes() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.windowTitle() == "Forensic Image Scanner"
    assert window.state.selected_page == "home"
    assert window.stack.count() == 6
    assert app is not None
