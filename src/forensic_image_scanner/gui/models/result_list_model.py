"""Qt model for a scalable result list."""

from __future__ import annotations

from PySide6.QtCore import QAbstractListModel, QModelIndex, Qt


class ResultItem:
    """A result record for the GUI result list."""

    def __init__(self, filename: str, path: str, risk: str = "—") -> None:
        self.filename = filename
        self.path = path
        self.risk = risk


class ResultListModel(QAbstractListModel):
    """Empty-safe list model designed for many rows without creating widgets."""

    def __init__(self, rows: list[ResultItem] | None = None, parent=None) -> None:
        super().__init__(parent)
        self._rows = rows or []

    def rowCount(self, parent: QModelIndex | None = None) -> int:  # noqa: ARG002
        return len(self._rows)

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        item = self._rows[index.row()]
        if role in {Qt.DisplayRole, Qt.EditRole}:
            return f"{item.filename} [{item.risk}]"
        if role == Qt.UserRole:
            return item
        return None

    def set_rows(self, rows: list[ResultItem]) -> None:
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()
