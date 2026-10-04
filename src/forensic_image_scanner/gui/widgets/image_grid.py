"""Large-result grid placeholder built for virtualized designs."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QLabel, QWidget


class ImageGrid(QWidget):
    """A lightweight grid designed to scale to many records later."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._layout = QGridLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(8)

        for row, col in ((0, 0), (0, 1), (1, 0), (1, 1)):
            tile = QLabel(f"Tile {row + col + 1}")
            tile.setStyleSheet(
                "background: #1f2937; border: 1px solid #374151; border-radius: 8px; "
                "padding: 24px; color: #e5e7eb;"
            )
            self._layout.addWidget(tile, row, col)
