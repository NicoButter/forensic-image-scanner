"""Simple container for evidence metadata."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QVBoxLayout, QWidget


class EvidenceCard(QWidget):
    """Card-like display for evidence details."""

    def __init__(self, title: str, parent=None) -> None:
        super().__init__(parent)
        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(6)

        title_label = QLabel(title)
        title_label.setStyleSheet("color: #d1d5db; font-weight: 600;")
        self._layout.addWidget(title_label)

        self.content = QLabel("Not available")
        self.content.setStyleSheet("color: #f3f4f6;")
        self._layout.addWidget(self.content)
