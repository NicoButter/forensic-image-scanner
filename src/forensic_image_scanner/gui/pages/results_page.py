"""Real analysis results with safe-review metadata presentation."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListView,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.gui.models.result_list_model import (
    ResultItemDelegate,
    ResultListModel,
)
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.results import ImageAnalysisResult


class ResultsPage(QWidget):
    """Filter and inspect metadata without automatically revealing evidence."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(16)

        filters = QVBoxLayout()
        filters.addWidget(QLabel("Triage filters"))
        self.filter_boxes: dict[str, QCheckBox] = {}
        for category in ("HIGH", "REVIEW", "LOW", "ERROR"):
            checkbox = QCheckBox(category)
            checkbox.setChecked(True)
            filters.addWidget(checkbox)
            self.filter_boxes[category] = checkbox
        filters.addStretch(1)
        layout.addLayout(filters, 0)

        center = QVBoxLayout()
        self.summary_label = QLabel("No analysis results")
        center.addWidget(self.summary_label)
        self.list_model = ResultListModel()
        self.list_view = QListView()
        self.list_view.setModel(self.list_model)
        self.list_view.setItemDelegate(ResultItemDelegate(self.list_view))
        center.addWidget(self.list_view)
        layout.addLayout(center, 2)

        detail = QVBoxLayout()
        self.preview_label = QLabel("Sensitive preview hidden")
        self.preview_label.setWordWrap(True)
        detail.addWidget(self.preview_label)
        self.detail_label = QLabel("Select a result to inspect metadata.")
        self.detail_label.setWordWrap(True)
        self.detail_label.setTextInteractionFlags(
            self.detail_label.textInteractionFlags()
            | Qt.TextInteractionFlag.TextSelectableByMouse
        )
        detail.addWidget(self.detail_label)
        detail.addStretch(1)
        layout.addLayout(detail, 2)

        for category, checkbox in self.filter_boxes.items():
            checkbox.toggled.connect(
                lambda enabled, name=category: self.list_model.set_category_enabled(
                    name, enabled
                )
            )
        self.list_view.selectionModel().currentChanged.connect(self._selection_changed)
        self.state.analysis_results_changed.connect(self.refresh)
        self.refresh()

    def refresh(self) -> None:
        rows = [
            result
            for result in self.state.analysis_results
            if isinstance(result, ImageAnalysisResult)
        ]
        self.list_model.set_rows(rows)
        summary = self.state.analysis_summary
        if summary is None:
            self.summary_label.setText("No analysis results")
        else:
            self.summary_label.setText(
                f"{summary.processed}/{summary.discovered} processed · "
                f"HIGH {summary.high} · REVIEW {summary.review} · "
                f"LOW {summary.low} · ERRORS {summary.errors}"
            )

    def _selection_changed(self, current, _previous) -> None:
        result = self.list_model.result_at(current.row())
        if result is None:
            return
        self._show_result(result)

    def _show_result(self, result: ImageAnalysisResult) -> None:
        score = "—" if result.nsfw_score is None else f"{result.nsfw_score:.6f}"
        self.preview_label.setText(f"Sensitive preview hidden\n\nNSFW score: {score}")
        triage = result.triage.value if result.triage is not None else "ERROR"
        self.detail_label.setText(
            "EVIDENCE\n"
            f"Filename: {result.filename}\nRelative path: {result.relative_path}\n"
            f"Size: {result.size_bytes} bytes\nMIME: {result.mime_type or 'unknown'}\n"
            f"SHA-256: {result.sha256}\n\n"
            "ANALYSIS\n"
            f"Model: {result.model_id}\nRevision: {result.model_revision}\n"
            f"Model SHA: {result.model_sha256}\n"
            f"Provenance: {result.provenance_status}\n\n"
            "RESULT\n"
            f"normal: {result.normal_score}\nnsfw: {result.nsfw_score}\n"
            f"triage: {triage}\nstatus: {result.status}\n"
            f"error: {result.error}\n\nHuman review required"
        )
