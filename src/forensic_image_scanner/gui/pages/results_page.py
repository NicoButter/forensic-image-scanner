"""Real analysis results and explicit, verified post-analysis actions."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from PySide6.QtCore import QItemSelectionModel, Qt, QThread, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListView,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.export_service import ExportService
from forensic_image_scanner.gui.models.result_list_model import (
    ResultItemDelegate,
    ResultListModel,
)
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.workers.export_worker import ExportWorker
from forensic_image_scanner.reports.csv_report import write_csv_report
from forensic_image_scanner.reports.json_report import write_json_report
from forensic_image_scanner.results import ImageAnalysisResult, SourceMode

MOVE_EVIDENCE_TOOLTIP = (
    "Moving files is disabled for evidence sources.\n"
    "Use Export to preserve the original evidence."
)


class ResultsPage(QWidget):
    """Metadata-only review plus explicit source-preserving transfer controls."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.export_worker: ExportWorker | None = None
        self.export_thread: QThread | None = None
        self._transfer_results: list[ImageAnalysisResult] = []
        self._transfer_is_move = False

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
        self.selected_label = QLabel("0 selected")
        center.addWidget(self.selected_label)
        self.list_model = ResultListModel()
        self.list_view = QListView()
        self.list_view.setModel(self.list_model)
        self.list_view.setItemDelegate(ResultItemDelegate(self.list_view))
        self.list_view.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        center.addWidget(self.list_view)

        selection_actions = QHBoxLayout()
        self.select_high_button = QPushButton("SELECT ALL HIGH")
        self.select_review_button = QPushButton("SELECT ALL REVIEW")
        self.clear_selection_button = QPushButton("CLEAR SELECTION")
        for button in (
            self.select_high_button,
            self.select_review_button,
            self.clear_selection_button,
        ):
            selection_actions.addWidget(button)
        center.addLayout(selection_actions)

        transfer_actions = QHBoxLayout()
        self.export_button = QPushButton("EXPORT SELECTED")
        self.move_button = QPushButton("MOVE SELECTED")
        self.open_output_button = QPushButton("OPEN OUTPUT DIRECTORY")
        for button in (self.export_button, self.move_button, self.open_output_button):
            transfer_actions.addWidget(button)
        center.addLayout(transfer_actions)
        self.transfer_progress = QProgressBar()
        self.transfer_progress.hide()
        center.addWidget(self.transfer_progress)
        self.cancel_transfer_button = QPushButton("CANCEL EXPORT")
        self.cancel_transfer_button.hide()
        center.addWidget(self.cancel_transfer_button)
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
                lambda enabled, name=category: self.list_model.set_category_enabled(name, enabled)
            )
        self.list_view.selectionModel().currentChanged.connect(self._selection_changed)
        self.list_view.selectionModel().selectionChanged.connect(self._selection_count_changed)
        self.select_high_button.clicked.connect(lambda: self._select_categories({"HIGH"}))
        self.select_review_button.clicked.connect(
            lambda: self._select_categories({"REVIEW"})
        )
        self.clear_selection_button.clicked.connect(self.list_view.clearSelection)
        self.export_button.clicked.connect(lambda: self._confirm_transfer(move=False))
        self.move_button.clicked.connect(lambda: self._confirm_transfer(move=True))
        self.open_output_button.clicked.connect(self._open_output_directory)
        self.cancel_transfer_button.clicked.connect(self._cancel_transfer)
        self.state.analysis_results_changed.connect(self.refresh)
        self.state.source_mode_changed.connect(lambda _mode: self._update_action_state())
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
        self._selection_count_changed()
        self._update_action_state()

    def _selection_changed(self, current, _previous) -> None:
        result = self.list_model.result_at(current.row())
        if result is not None:
            self._show_result(result)

    def _selection_count_changed(self, *_args) -> None:
        count = len(self._selected_results())
        self.selected_label.setText(f"{count} selected")
        self._update_action_state()

    def _selected_results(self) -> list[ImageAnalysisResult]:
        indexes = self.list_view.selectionModel().selectedIndexes()
        seen: set[str] = set()
        selected: list[ImageAnalysisResult] = []
        for index in indexes:
            result = self.list_model.result_at(index.row())
            if result is not None and str(result.path) not in seen:
                seen.add(str(result.path))
                selected.append(result)
        return selected

    def _select_categories(self, categories: set[str]) -> None:
        selection = self.list_view.selectionModel()
        selection.clearSelection()
        for row in range(self.list_model.rowCount()):
            result = self.list_model.result_at(row)
            category = "ERROR" if result is not None and result.status == "error" else (
                result.triage.value if result is not None and result.triage is not None else "ERROR"
            )
            if category in categories:
                selection.select(
                    self.list_model.index(row, 0),
                    QItemSelectionModel.SelectionFlag.Select
                    | QItemSelectionModel.SelectionFlag.Rows,
                )
        self._selection_count_changed()

    def _update_action_state(self) -> None:
        selected = bool(self._selected_results())
        active = self.export_thread is not None
        self.export_button.setEnabled(selected and not active)
        working_copy = self.state.source_mode is SourceMode.WORKING_COPY
        self.move_button.setEnabled(selected and working_copy and not active)
        self.move_button.setToolTip("" if working_copy else MOVE_EVIDENCE_TOOLTIP)
        self.open_output_button.setEnabled(bool(self.state.output_directory) and not active)

    def _confirm_transfer(self, *, move: bool) -> None:
        selected = self._selected_results()
        if not selected:
            return
        if not self.state.output_directory or self.state.analysis_summary is None:
            QMessageBox.warning(
                self, "Output unavailable", "Choose a report output directory first."
            )
            return
        if move and self.state.source_mode is not SourceMode.WORKING_COPY:
            QMessageBox.warning(self, "Move disabled", MOVE_EVIDENCE_TOOLTIP)
            return
        counts = {"HIGH": 0, "REVIEW": 0, "LOW": 0, "ERROR": 0}
        for result in selected:
            category = "ERROR" if result.status == "error" else result.triage.value
            counts[category] += 1
        if move:
            text = (
                f"Move {len(selected)} selected files?\n\n"
                "This will remove files from the source working directory only after "
                "verified copies are created.\n\n"
                "This operation cannot be undone by the application."
            )
            title, confirm = "Move selected files", "Move Files"
        else:
            text = (
                f"Export {len(selected)} selected files?\n\n"
                f"HIGH      {counts['HIGH']}\nREVIEW    {counts['REVIEW']}\n"
                f"LOW       {counts['LOW']}\nERROR     {counts['ERROR']}\n\n"
                f"Destination:\n{Path(self.state.output_directory) / 'exported'}"
            )
            title, confirm = "Export selected files", "Export"
        dialog = QMessageBox(self)
        dialog.setIcon(QMessageBox.Icon.Warning if move else QMessageBox.Icon.Question)
        dialog.setWindowTitle(title)
        dialog.setText(text)
        dialog.setStandardButtons(QMessageBox.StandardButton.Cancel)
        confirm_button = dialog.addButton(confirm, QMessageBox.ButtonRole.AcceptRole)
        dialog.exec()
        if dialog.clickedButton() is confirm_button:
            self._start_transfer(selected, move=move)

    def _start_transfer(self, selected: list[ImageAnalysisResult], *, move: bool) -> None:
        summary = self.state.analysis_summary
        assert summary is not None
        self._transfer_results = []
        self._transfer_is_move = move
        service = ExportService(summary.source, summary.output)
        self.export_worker = ExportWorker(
            service,
            selected,
            move=move,
            source_mode=self.state.source_mode,
        )
        self.export_thread = QThread(self)
        self.export_worker.moveToThread(self.export_thread)
        self.export_thread.started.connect(self.export_worker.run)
        self.export_worker.started.connect(self._transfer_started)
        self.export_worker.file_started.connect(self._transfer_file_started)
        self.export_worker.file_completed.connect(self._transfer_file_completed)
        self.export_worker.progress.connect(self._transfer_progressed)
        self.export_worker.completed.connect(self._transfer_completed)
        self.export_worker.cancelled.connect(self._transfer_cancelled)
        self.export_worker.failed.connect(self._transfer_failed)
        self.export_worker.finished.connect(self.export_worker.deleteLater)
        self.export_worker.finished.connect(self.export_thread.quit)
        self.export_thread.finished.connect(self._transfer_thread_finished)
        action = "move" if move else "export"
        self.state.add_audit_event(f"{action} requested: {len(selected)} files")
        self._update_action_state()
        self.export_thread.start()

    def _transfer_started(self, total: int) -> None:
        self.transfer_progress.setRange(0, total)
        self.transfer_progress.setValue(0)
        self.transfer_progress.show()
        self.cancel_transfer_button.setText(
            "CANCEL MOVE" if self._transfer_is_move else "CANCEL EXPORT"
        )
        self.cancel_transfer_button.show()

    def _transfer_file_completed(self, result: ImageAnalysisResult) -> None:
        self._transfer_results.append(result)
        label = "MOVE" if self._transfer_is_move else "EXPORT"
        self.summary_label.setText(f"{label} completed for {result.relative_path}")

    def _transfer_file_started(self, index: int, total: int, relative_path: str) -> None:
        label = "Moving" if self._transfer_is_move else "Exporting"
        self.summary_label.setText(f"{label} results\n{index - 1} / {total}\n{relative_path}")

    def _transfer_progressed(self, current: int, total: int) -> None:
        self.transfer_progress.setValue(current)
        self.transfer_progress.setFormat(f"{current} / {total}")

    def _transfer_completed(self, _results: object) -> None:
        self._persist_transfer_results(cancelled=False)

    def _transfer_cancelled(self, _results: object) -> None:
        self._persist_transfer_results(cancelled=True)

    def _persist_transfer_results(self, *, cancelled: bool) -> None:
        if not self._transfer_results:
            return
        updates = {str(result.path): result for result in self._transfer_results}
        all_results = [
            updates.get(str(result.path), result)
            for result in self.state.analysis_results
            if isinstance(result, ImageAnalysisResult)
        ]
        summary = self.state.analysis_summary
        assert summary is not None
        updated_summary = replace(summary, results=tuple(all_results))
        write_json_report(all_results, summary.json_path)
        write_csv_report(all_results, summary.csv_path)
        self.state.set_analysis_results(all_results, updated_summary)
        action = "move" if self._transfer_is_move else "export"
        suffix = " cancelled; completed files preserved" if cancelled else " completed"
        self.state.add_audit_event(f"{action}{suffix}: {len(self._transfer_results)} files")

    def _transfer_failed(self, message: str) -> None:
        self.state.add_audit_event(f"transfer worker failed: {message}")
        QMessageBox.critical(self, "Transfer failed", message)

    def _cancel_transfer(self) -> None:
        if self.export_worker is not None:
            self.cancel_transfer_button.setEnabled(False)
            self.cancel_transfer_button.setText("Cancelling after current file…")
            self.export_worker.cancel()

    def _transfer_thread_finished(self) -> None:
        if self.export_thread is not None:
            self.export_thread.deleteLater()
        self.export_worker = None
        self.export_thread = None
        self.transfer_progress.hide()
        self.cancel_transfer_button.hide()
        self.cancel_transfer_button.setEnabled(True)
        self._update_action_state()

    def _open_output_directory(self) -> None:
        if self.state.output_directory:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(self.state.output_directory))))

    def _show_result(self, result: ImageAnalysisResult) -> None:
        score = "—" if result.nsfw_score is None else f"{result.nsfw_score:.6f}"
        self.preview_label.setText(f"Sensitive preview hidden\n\nNSFW score: {score}")
        triage = result.triage.value if result.triage is not None else "ERROR"
        exported = str(result.exported_path) if result.exported_path is not None else "—"
        move_status = result.move_status.value if result.move_status else "—"
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
            f"error: {result.error}\n\n"
            "EXPORT\n"
            f"status: {result.export_status.value}\n"
            f"destination: {exported}\n"
            f"destination SHA-256: {result.exported_sha256 or '—'}\n"
            f"source verified: {result.source_verified_before_export}\n"
            f"move status: {move_status}\n"
            f"source removed: {result.source_removed}\n\nHuman review required"
        )
