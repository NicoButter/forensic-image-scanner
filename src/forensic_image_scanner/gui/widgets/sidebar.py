"""Sidebar navigation widget."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QPushButton, QVBoxLayout, QWidget


class Sidebar(QWidget):
    """Left navigation panel with a fixed process flow."""

    page_requested = Signal(str)

    def __init__(
        self,
        page_labels: list[str],
        page_keys: list[str] | None = None,
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.page_labels = page_labels
        self.page_keys = page_keys or [str(index) for index in range(len(page_labels))]
        self.buttons: dict[str, QPushButton] = {}
        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(12, 12, 12, 12)

        for label, key in zip(page_labels, self.page_keys, strict=True):
            button = QPushButton(label)
            button.setCheckable(True)
            button.setObjectName("nav-button")
            button.setStyleSheet(
                "QPushButton#nav-button { background: #1f2937; color: #e5e7eb; "
                "border: 1px solid #374151; border-radius: 8px; padding: 12px; text-align: left; }"
                "QPushButton#nav-button:checked { background: #0f172a; border-color: #60a5fa; }"
            )
            button.clicked.connect(lambda checked, page_key=key: self.page_requested.emit(page_key))
            self._layout.addWidget(button)
            self.buttons[key] = button

    def set_active(self, page_key: str) -> None:
        for key, button in self.buttons.items():
            button.setChecked(key == page_key)
