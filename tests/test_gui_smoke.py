"""Smoke tests for the optional Qt desktop GUI."""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from forensic_image_scanner.gui import create_application, main
from forensic_image_scanner.gui.main_window import MainWindow
from forensic_image_scanner.gui.state.application_state import ApplicationState


def test_gui_entry_points_are_importable() -> None:
    assert callable(create_application)
    assert callable(main)


def test_main_window_initializes() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()
    assert window.windowTitle() == "Forensic Image Scanner"
    assert window.state.selected_page == "home"
    assert window.stack.count() == 6
    assert window.network_badge.text() == "ANALYSIS OFFLINE"
    assert window.model_badge.text() == "NO MODEL"
    assert app is not None


def test_home_actions_use_central_navigation() -> None:
    app = QApplication.instance() or QApplication([])
    window = MainWindow()

    window.pages["home"].action_buttons["models"].click()

    assert window.state.selected_page == "models"
    assert window.stack.currentWidget() is window.pages["models"]
    assert window.sidebar.buttons["models"].isChecked()
    assert app is not None


def test_network_badge_reflects_explicit_model_install_activity() -> None:
    app = QApplication.instance() or QApplication([])
    state = ApplicationState()
    window = MainWindow(state)

    state.model_download_active = True
    assert window.network_badge.text() == "NETWORK ACTIVE · MODEL INSTALL"
    state.model_download_active = False
    assert window.network_badge.text() == "ANALYSIS OFFLINE"
    assert app is not None
