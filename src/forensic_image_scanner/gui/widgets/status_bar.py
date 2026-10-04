"""Compact application status bar."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QWidget


class StatusBar(QWidget):
    """Status bar with compact forensic metadata."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 6, 12, 6)

        self.left_label = QLabel("Scanner 0.1.0")
        self.left_label.setStyleSheet("color: #e5e7eb; font-weight: 600;")
        self._layout.addWidget(self.left_label)

        self._layout.addStretch(1)

        self.cpu_label = QLabel("CPU")
        self.python_label = QLabel("Python 3.14.x")
        self.offline_label = QLabel("OFFLINE")
        self.readonly_label = QLabel("Evidence read-only")

        for label in (self.cpu_label, self.python_label, self.offline_label, self.readonly_label):
            label.setStyleSheet("color: #9ca3af; background: transparent;")
            self._layout.addWidget(label)
