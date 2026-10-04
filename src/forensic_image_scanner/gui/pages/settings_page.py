"""Minimal configuration page."""

from __future__ import annotations

from PySide6.QtWidgets import QCheckBox, QFormLayout, QLabel, QLineEdit, QWidget

from forensic_image_scanner.gui.state.application_state import ApplicationState


class SettingsPage(QWidget):
    """Minimal configuration screen with read-only-first defaults."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self._layout = QFormLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)

        self._layout.addRow(QLabel("Theme"), QLineEdit("Dark"))
        self._layout.addRow(QLabel("Model directory"), QLineEdit("/controlled/models"))
        self._layout.addRow(QLabel("Default report directory"), QLineEdit("/tmp/reports"))
        self.safe_review = QCheckBox("Safe Review Mode")
        self.safe_review.setChecked(True)
        self._layout.addRow(QLabel(""), self.safe_review)
