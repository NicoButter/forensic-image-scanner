"""Analyze page for evidence source and pre-scan information."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QThread, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.gui.services.model_service import ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.workers.analysis_worker import AnalysisWorker
from forensic_image_scanner.gui.workers.discovery_worker import DiscoveryWorker


class AnalyzePage(QWidget):
    """Primary analysis interface with a read-only guardrail model."""

    navigate_requested = Signal(str)

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self.source_path = self.state.selected_source
        self.output_directory = self.state.output_directory
        self.discovery_worker = None
        self.discovery_thread = None
        self.analysis_worker: AnalysisWorker | None = None
        self.analysis_thread: QThread | None = None
        self.analysis_started_at = 0.0
        self.analysis_counts = {"LOW": 0, "REVIEW": 0, "HIGH": 0, "ERROR": 0}
        self._refreshing_models = False

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        title = QLabel("Analyze")
        title.setStyleSheet("color: #edf2f7; font-size: 22px; font-weight: 700;")
        root.addWidget(title)

        form = QFormLayout()
        self.source_edit = QLineEdit(self.source_path)
        self.source_edit.setPlaceholderText("/path/to/evidence")
        self.source_button = QPushButton("Browse")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_edit)
        source_row.addWidget(self.source_button)
        form.addRow("Evidence source", source_row)

        self.output_edit = QLineEdit(self.output_directory)
        self.output_button = QPushButton("Browse")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_row.addWidget(self.output_button)
        form.addRow("Report output directory", output_row)

        self.model_combo = QComboBox()
        self.model_combo.setPlaceholderText("Select model")
        form.addRow("Model", self.model_combo)

        self.manage_models_button = QPushButton("MANAGE MODELS")
        self.manage_models_button.clicked.connect(
            lambda: self.navigate_requested.emit("models")
        )
        form.addRow("", self.manage_models_button)

        root.addLayout(form)

        self.status_label = QLabel("No source selected")
        self.status_label.setProperty("secondary", True)
        root.addWidget(self.status_label)

        self.options = []
        options = QGridLayout()
        for index, label in enumerate([
            "Recursive directories",
            "SHA-256 original files",
            "Skip already processed files",
            "Safe Review Mode",
        ]):
            checkbox = QCheckBox(label)
            checkbox.setChecked(index in (0, 1, 3))
            if index == 3:
                checkbox.setChecked(True)
            self.options.append(checkbox)
            options.addWidget(checkbox, index // 2, index % 2)
        root.addLayout(options)

        self.preview = QLabel("Files discovered\n0\n\nTotal size\n0 bytes")
        self.preview.setStyleSheet(
            "color: #edf2f7; background: #0f172a; border: 1px solid #2f3b4d; "
            "padding: 12px; border-radius: 8px;"
        )
        root.addWidget(self.preview)

        self.discover_button = QPushButton("DISCOVER IMAGES")
        self.discover_button.clicked.connect(self.discover_images)
        root.addWidget(self.discover_button)

        self.start_button = QPushButton("START ANALYSIS")
        self.start_button.setEnabled(False)
        self.start_button.setStyleSheet(
            "QPushButton { background: #2563eb; color: #f8fafc; border: none; padding: 12px; "
            "border-radius: 8px; font-weight: 700; } "
            "QPushButton:disabled { background: #374151; color: #9ca3af; }"
        )
        self.start_button.clicked.connect(self._handle_start_analysis)
        root.addWidget(self.start_button)

        self.analysis_progress = QProgressBar()
        self.analysis_progress.hide()
        root.addWidget(self.analysis_progress)
        self.cancel_button = QPushButton("CANCEL")
        self.cancel_button.hide()
        self.cancel_button.clicked.connect(self._cancel_analysis)
        root.addWidget(self.cancel_button)
        self.pause_button = QPushButton("PAUSE — COMING LATER")
        self.pause_button.setEnabled(False)
        self.pause_button.hide()
        root.addWidget(self.pause_button)

        self.source_button.clicked.connect(self._select_source)
        self.output_button.clicked.connect(self._select_output)
        self.model_combo.currentTextChanged.connect(self._update_start_state)
        self._populate_models()
        self.model_combo.currentIndexChanged.connect(self._on_model_selected)
        self.state.model_status_changed.connect(lambda _model_id: self._populate_models())
        if self.model_combo.currentIndex() >= 0:
            self._on_model_selected(self.model_combo.currentIndex())
        self._update_start_state()

    def _populate_models(self) -> None:
        self._refreshing_models = True
        self.model_combo.clear()
        models = self.model_service.available_models()
        for model in models:
            if not model.installed or self.state.model_verification(model.model_id) is not True:
                continue
            display_name = (
                "Falconsai NSFW Image Detection"
                if model.model_id == "falconsai-nsfw-image-detection"
                else model.model_id
            )
            label = f"{display_name} — Verified · {model.provenance.title()} provenance"
            self.model_combo.addItem(label, model.model_id)
        if not self.model_combo.count():
            self.model_combo.addItem("No usable model installed")
            self.manage_models_button.show()
        else:
            self.manage_models_button.hide()
        self.model_combo.setCurrentIndex(-1)
        if self.state.selected_model:
            index = self.model_combo.findData(self.state.selected_model)
            if index >= 0:
                self.model_combo.setCurrentIndex(index)
        self._refreshing_models = False
        self._update_start_state()

    def _select_source(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select evidence directory")
        if not directory:
            return
        self.source_path = directory
        self.state.selected_source = directory
        self.source_edit.setText(directory)
        self._validate_source()
        self._update_start_state()

    def _on_model_selected(self, _index: int) -> None:
        if self._refreshing_models:
            return
        model_id = self.model_combo.currentData()
        if isinstance(model_id, str):
            self.state.selected_model = model_id

    def _select_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select report output directory")
        if not directory:
            return
        self.output_directory = directory
        self.state.output_directory = directory
        self.output_edit.setText(directory)
        self._validate_output()
        self._update_start_state()

    def _validate_source(self) -> None:
        if not self.source_path:
            self.status_label.setText("No source selected")
            return
        path = Path(self.source_path)
        if not path.exists() or not path.is_dir():
            self.status_label.setText("Evidence source is not a valid directory.")
            return
        self.status_label.setText("Read-only source selected")

    def _validate_output(self) -> None:
        if not self.output_directory:
            return
        source = Path(self.source_path).resolve() if self.source_path else None
        output = Path(self.output_directory).resolve()
        if source is not None and output.is_relative_to(source):
            self.status_label.setText("Output directory cannot be inside the evidence directory.")
            self.output_directory = ""
            self.output_edit.clear()
        elif output.exists() and not output.is_dir():
            self.status_label.setText("Output directory must be a directory.")
        elif not output.exists():
            self.status_label.setText("Output directory will be created on first use.")

    def _update_start_state(self) -> None:
        source_ok = (
            bool(self.source_path)
            and Path(self.source_path).exists()
            and Path(self.source_path).is_dir()
        )
        output = Path(self.output_directory) if self.output_directory else None
        output_ok = bool(
            output is not None and (not output.exists() or output.is_dir())
        )
        model_id = self.model_combo.currentData()
        model_ok = bool(
            model_id
            and model_id not in {"", "No usable model installed"}
            and self.state.model_verification(str(model_id)) is True
        )
        ready = (
            source_ok
            and output_ok
            and model_ok
            and self.state.discovery_completed
            and self.analysis_thread is None
        )
        self.start_button.setEnabled(ready)
        if not source_ok:
            self.status_label.setText("Select a valid evidence directory.")
        elif not output_ok:
            self.status_label.setText("Select a valid output directory.")
        elif not model_ok:
            self.status_label.setText("Select a verified model from the registry.")
        elif not self.state.discovery_completed:
            self.status_label.setText("Run discovery before starting analysis.")

    def _handle_start_analysis(self) -> None:
        if not self.start_button.isEnabled():
            return
        model_id = self.model_combo.currentData()
        request = AnalysisRequest(
            source=Path(self.source_path),
            output=Path(self.output_directory),
            model=str(model_id),
            recursive=bool(self.options[0].isChecked()),
            sha256=bool(self.options[1].isChecked()),
            safe_review=bool(self.options[3].isChecked()),
        )
        service = AnalysisService(self.model_service.model_root)
        self.analysis_worker = AnalysisWorker(service, request)
        self.analysis_thread = QThread(self)
        self.analysis_worker.moveToThread(self.analysis_thread)
        self.analysis_thread.started.connect(self.analysis_worker.run)
        self.analysis_worker.started.connect(self._analysis_started)
        self.analysis_worker.file_started.connect(self._analysis_file_started)
        self.analysis_worker.file_completed.connect(self._analysis_file_completed)
        self.analysis_worker.progress.connect(self._analysis_progress_changed)
        self.analysis_worker.error.connect(self._analysis_file_error)
        self.analysis_worker.completed.connect(self._analysis_completed)
        self.analysis_worker.cancelled.connect(self._analysis_cancelled)
        self.analysis_worker.failed.connect(self._analysis_failed)
        self.analysis_worker.finished.connect(self.analysis_worker.deleteLater)
        self.analysis_worker.finished.connect(self.analysis_thread.quit)
        self.analysis_thread.finished.connect(self._analysis_thread_finished)
        self.state.analysis_state = "analyzing"
        self.state.add_audit_event("analysis started")
        self.state.add_audit_event(f"model verified: {model_id}")
        self.state.add_audit_event(
            f"discovery count: {self.state.discovery_summary.get('total_images', 0)}"
        )
        self.analysis_started_at = time.monotonic()
        self.analysis_counts = {"LOW": 0, "REVIEW": 0, "HIGH": 0, "ERROR": 0}
        self.start_button.setEnabled(False)
        self.status_label.setText("Initializing verified offline model…")
        self.analysis_progress.show()
        self.cancel_button.show()
        self.pause_button.show()
        self.analysis_thread.start()

    def _analysis_started(self, total: int) -> None:
        self.analysis_progress.setRange(0, total)
        self.analysis_progress.setValue(0)
        self.status_label.setText(f"ANALYZING EVIDENCE\n0 / {total}")

    def _analysis_file_started(self, index: int, total: int, path: str) -> None:
        self.status_label.setText(
            f"ANALYZING EVIDENCE\n{index - 1} / {total}\n\nCurrent\n{Path(path).name}"
        )

    def _analysis_file_completed(self, result: object) -> None:
        if getattr(result, "status", "error") == "error":
            self.analysis_counts["ERROR"] += 1
        else:
            self.analysis_counts[result.triage.value] += 1

    def _analysis_progress_changed(self, current: int, total: int) -> None:
        self.analysis_progress.setValue(current)
        elapsed = int(time.monotonic() - self.analysis_started_at)
        self.preview.setText(
            f"Processed\n{current} / {total}\n\n"
            f"LOW       {self.analysis_counts['LOW']}\n"
            f"REVIEW    {self.analysis_counts['REVIEW']}\n"
            f"HIGH      {self.analysis_counts['HIGH']}\n"
            f"ERRORS    {self.analysis_counts['ERROR']}\n\n"
            f"Elapsed\n{elapsed // 60:02d}:{elapsed % 60:02d}"
        )

    def _analysis_file_error(self, path: str, message: str) -> None:
        self.state.add_audit_event(f"file analysis error: {Path(path).name}: {message}")

    def _store_summary(self, summary: object) -> None:
        self.state.set_analysis_results(list(summary.results), summary)
        self.state.add_audit_event("result export completed")
        self.preview.setText(
            f"Files discovered     {summary.discovered}\n"
            f"Processed            {summary.processed}\n"
            f"LOW                  {summary.low}\n"
            f"REVIEW               {summary.review}\n"
            f"HIGH                 {summary.high}\n"
            f"Errors               {summary.errors}\n\n"
            f"Elapsed              {summary.elapsed_seconds:.2f}s"
        )

    def _analysis_completed(self, summary: object) -> None:
        self._store_summary(summary)
        self.state.analysis_state = "completed"
        self.state.add_audit_event("analysis completed")
        self.status_label.setText("Analysis complete")
        self.navigate_requested.emit("results")

    def _analysis_cancelled(self, summary: object) -> None:
        self._store_summary(summary)
        self.state.analysis_state = "cancelled"
        self.state.add_audit_event("analysis cancelled")
        self.status_label.setText("CANCELLED — completed results were preserved")

    def _analysis_failed(self, message: str) -> None:
        self.state.analysis_state = "error"
        self.status_label.setText(f"Analysis unavailable: {message}")
        QMessageBox.critical(self, "Analysis failed", message)

    def _cancel_analysis(self) -> None:
        if self.analysis_worker is not None:
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Cancelling after current image…")
            self.analysis_worker.cancel()

    def _analysis_thread_finished(self) -> None:
        if self.analysis_thread is not None:
            self.analysis_thread.deleteLater()
        self.analysis_worker = None
        self.analysis_thread = None
        self.cancel_button.hide()
        self.cancel_button.setEnabled(True)
        self.pause_button.hide()
        self._update_start_state()

    def discover_images(self) -> None:
        if not self.source_path:
            self.status_label.setText("Select an evidence source before discovery.")
            return
        self.state.analysis_state = "discovering"
        self.status_label.setText("Scanning directory...")
        self.discovery_thread = QThread(self)
        self.discovery_worker = DiscoveryWorker(
            self.source_path, recursive=bool(self.options[0].isChecked())
        )
        self.discovery_worker.moveToThread(self.discovery_thread)
        self.discovery_worker.progress.connect(lambda message: self.status_label.setText(message))
        self.discovery_worker.completed.connect(self._on_discovery_completed)
        self.discovery_worker.failed.connect(self._on_discovery_failed)
        self.discovery_thread.started.connect(self.discovery_worker.run)
        self.discovery_worker.finished = getattr(self.discovery_worker, "finished", None)
        self.discovery_thread.start()

    def _on_discovery_completed(self, summary: dict[str, object]) -> None:
        self.state.discovery_summary = summary
        self.state.discovery_completed = True
        self.state.selected_source = str(summary.get("source", self.source_path))
        self.state.analysis_state = "discovery_complete"
        total = int(summary.get("total_images", 0))
        counts = summary.get("counts", {})
        preview = [f"Files discovered\n{total}", "", "Total size\nNot available", ""]
        for label, count in sorted(counts.items()):
            preview.append(f"{label}\n{count}")
        self.preview.setText("\n".join(preview))
        self.status_label.setText("Discovery completed")
        self._update_start_state()
        self.discovery_thread.quit()

    def _on_discovery_failed(self, message: str) -> None:
        self.state.discovery_completed = False
        self.state.analysis_state = "error"
        self.status_label.setText(message)
        if self.discovery_thread is not None:
            self.discovery_thread.quit()
