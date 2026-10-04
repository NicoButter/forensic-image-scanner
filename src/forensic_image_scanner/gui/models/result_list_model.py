"""Scalable Qt list model for real analysis results."""

from __future__ import annotations

from PySide6.QtCore import QAbstractListModel, QModelIndex, QSize, Qt
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem

from forensic_image_scanner.results import ImageAnalysisResult


class ResultListModel(QAbstractListModel):
    """Store metadata-only rows without constructing a widget per result."""

    ResultRole = Qt.ItemDataRole.UserRole + 1

    def __init__(
        self, rows: list[ImageAnalysisResult] | None = None, parent=None
    ) -> None:
        super().__init__(parent)
        self._all_rows = rows or []
        self._rows = list(self._all_rows)
        self._enabled = {"HIGH", "REVIEW", "LOW", "ERROR"}
        self._sort()

    def rowCount(self, parent: QModelIndex | None = None) -> int:
        return 0 if parent is not None and parent.isValid() else len(self._rows)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or index.row() >= len(self._rows):
            return None
        result = self._rows[index.row()]
        if role in {Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole}:
            category = "ERROR" if result.status == "error" else result.triage.value
            score = "—" if result.nsfw_score is None else f"{result.nsfw_score:.4f}"
            transfer = (
                result.move_status.value if result.move_status else result.export_status.value
            )
            return f"{category:<7}  {score}  {result.relative_path}  [{transfer}]"
        if role in {Qt.ItemDataRole.UserRole, self.ResultRole}:
            return result
        return None

    def set_rows(self, rows: list[ImageAnalysisResult]) -> None:
        self.beginResetModel()
        self._all_rows = list(rows)
        self._apply_filter()
        self.endResetModel()

    def set_category_enabled(self, category: str, enabled: bool) -> None:
        if enabled:
            self._enabled.add(category)
        else:
            self._enabled.discard(category)
        self.beginResetModel()
        self._apply_filter()
        self.endResetModel()

    def result_at(self, row: int) -> ImageAnalysisResult | None:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def _apply_filter(self) -> None:
        self._rows = [
            result
            for result in self._all_rows
            if ("ERROR" if result.status == "error" else result.triage.value)
            in self._enabled
        ]
        self._sort()

    def _sort(self) -> None:
        self._rows.sort(
            key=lambda result: (
                result.nsfw_score is not None,
                result.nsfw_score if result.nsfw_score is not None else -1.0,
            ),
            reverse=True,
        )


class ResultItemDelegate(QStyledItemDelegate):
    """Compact metadata-only delegate; intentionally renders no thumbnail."""

    def sizeHint(self, option: QStyleOptionViewItem, index: QModelIndex) -> QSize:
        hint = super().sizeHint(option, index)
        return QSize(hint.width(), max(42, hint.height()))
