"""Compact application status bar."""

from __future__ import annotations

import platform

from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget


class StatusBar(QWidget):
    """Status bar with compact forensic metadata."""

    def __init__(self, scanner_version: str = "0.1.0", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 6, 12, 6)

        self.left_label = QLabel(f"Scanner {scanner_version}")
        self.left_label.setStyleSheet("color: #edf2f7; font-weight: 600;")
        self._layout.addWidget(self.left_label)

        self._layout.addStretch(1)

        cpu_label = QLabel("CPU")
        python_label = QLabel(f"Python {platform.python_version()}")
        offline_label = QLabel("OFFLINE")
        readonly_label = QLabel("Evidence read-only")

        for label in (cpu_label, python_label, offline_label, readonly_label):
            label.setStyleSheet("color: #a9b4c7; background: transparent;")
            self._layout.addWidget(label)
