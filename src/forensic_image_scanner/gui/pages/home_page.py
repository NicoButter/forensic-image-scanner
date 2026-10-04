"""Home page for the forensic desktop app."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class HomePage(QWidget):
    """Landing page for triage and workflow navigation."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)

        title = QLabel("Forensic Image Scanner")
        title.setStyleSheet("color: #f3f4f6; font-size: 26px; font-weight: 700;")
        self._layout.addWidget(title)

        subtitle = QLabel("Local image content triage\nOffline · Read-only · Auditable")
        subtitle.setStyleSheet("color: #d1d5db; font-size: 13px; line-height: 1.5;")
        self._layout.addWidget(subtitle)

        summary = QGridLayout()
        summary.setColumnStretch(0, 1)
        summary.setColumnStretch(1, 1)

        fields = [
            ("Active model", "Not available"),
            ("Model Registry", "No usable model installed."),
            ("Last case", "Not available"),
            ("Last analysis", "No analysis session created yet."),
        ]
        for index, (label, value) in enumerate(fields):
            label_widget = QLabel(label)
            value_widget = QLabel(value)
            label_widget.setStyleSheet("color: #9ca3af; font-weight: 600;")
            value_widget.setStyleSheet("color: #f3f4f6;")
            summary.addWidget(label_widget, index // 2, 0)
            summary.addWidget(value_widget, index // 2, 1)
        self._layout.addLayout(summary)

        actions = QGridLayout()
        for index, button_name in enumerate(("New analysis", "Open results", "Manage models")):
            button = QPushButton(button_name)
            button.setStyleSheet(
                "QPushButton { background: #1f2937; color: #f3f4f6; border: 1px solid #374151; "
                "padding: 10px; border-radius: 8px; }"
            )
            actions.addWidget(button, 0, index)
        self._layout.addLayout(actions)
