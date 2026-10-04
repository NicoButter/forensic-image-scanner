"""Audit page for case metadata and event log."""

from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QListWidget, QVBoxLayout, QWidget


class AuditPage(QWidget):
    """Case metadata and structured audit log entry list."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Audit")
        title.setStyleSheet("color: #f3f4f6; font-size: 22px; font-weight: 700;")
        self._layout.addWidget(title)

        form = QFormLayout()
        rows = [
            ("Case ID", "Not available"),
            ("Start timestamp", "Not available"),
            ("Source", "Not available"),
            ("Output", "Not available"),
            ("Scanner version", "0.1.0"),
            ("Python version", "3.14.x"),
            ("Model", "Not available"),
        ]
        for key, value in rows:
            form.addRow(QLabel(key), QLabel(value))
        self._layout.addLayout(form)

        self.log = QListWidget()
        self.log.addItems([
            "19:14:03  Case created",
            "19:14:05  Model verified",
            "19:14:06  Analysis started",
        ])
        self._layout.addWidget(self.log)
