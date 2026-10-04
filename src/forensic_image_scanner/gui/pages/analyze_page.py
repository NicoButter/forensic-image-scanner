"""Analyze page for evidence source and pre-scan information."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QThread
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
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.gui.services.model_service import ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.workers.discovery_worker import DiscoveryWorker


class AnalyzePage(QWidget):
    """Primary analysis interface with a read-only guardrail model."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self.source_path = self.state.selected_source
        self.output_directory = self.state.output_directory
        self.discovery_worker = None
        self.discovery_thread = None

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

        self.source_button.clicked.connect(self._select_source)
        self.output_button.clicked.connect(self._select_output)
        self.model_combo.currentTextChanged.connect(self._update_start_state)
        self._populate_models()
        self.model_combo.currentIndexChanged.connect(self._on_model_selected)
        if self.model_combo.currentIndex() >= 0:
            self._on_model_selected(self.model_combo.currentIndex())
        self._update_start_state()

    def _populate_models(self) -> None:
        self.model_combo.clear()
        models = self.model_service.available_models()
        for model in models:
            if not model.installed or not model.verified:
                continue
            label = f"{model.model_id} ({model.status})"
            self.model_combo.addItem(label, model.model_id)
        if not self.model_combo.count():
            self.model_combo.addItem("No usable model installed")
        self.model_combo.setCurrentIndex(-1)
        if self.state.selected_model:
            index = self.model_combo.findData(self.state.selected_model)
            if index >= 0:
                self.model_combo.setCurrentIndex(index)

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
        model_id = self.model_combo.currentData()
        if isinstance(model_id, str):
            self.state.selected_model = model_id
            self.state.record_model_verification(
                model_id, self.model_service.verify_model(model_id)
            )

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
        elif not output.exists():
            self.status_label.setText("Output directory will be created on first use.")
        elif not output.exists() or not output.is_dir():
            self.status_label.setText("Output directory must be a directory.")

    def _update_start_state(self) -> None:
        source_ok = (
            bool(self.source_path)
            and Path(self.source_path).exists()
            and Path(self.source_path).is_dir()
        )
        output_ok = (
            bool(self.output_directory)
            and Path(self.output_directory).exists()
            and Path(self.output_directory).is_dir()
        )
        model_id = self.model_combo.currentData()
        model_ok = bool(model_id and model_id not in {"", "No usable model installed"})
        ready = source_ok and output_ok and model_ok and self.state.discovery_completed
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
            self.status_label.setText("Analysis engine is not enabled in this development build.")
            return
        QMessageBox.information(
            self,
            "Development build",
            "Analysis engine is not enabled in this development build.",
        )

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
