"""Metadata panel for result details."""

from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QWidget


class MetadataPanel(QWidget):
    """Inspector panel for a selected evidence item."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._layout = QFormLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)

        fields = [
            ("Filename", "not available"),
            ("Path", "not available"),
            ("SHA-256", "not available"),
            ("Model", "not available"),
            ("Result", "normal"),
        ]
        for name, value in fields:
            self._layout.addRow(QLabel(name), QLabel(value))
