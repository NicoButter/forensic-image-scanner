"""Analyze page for evidence source and pre-scan information."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QButtonGroup,
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
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.analysis_service import AnalysisService
from forensic_image_scanner.detectors.nudenet import DEFAULT_VARIANT, NUDENET_VARIANTS
from forensic_image_scanner.gui.services.model_service import ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.workers.analysis_worker import AnalysisWorker
from forensic_image_scanner.gui.workers.discovery_worker import DiscoveryWorker
from forensic_image_scanner.gui.workers.recovery_worker import (
    PipelineWorker,
    RecoveryExecutionWorker,
    RecoveryWorker,
)
from forensic_image_scanner.pipeline import PipelineRequest
from forensic_image_scanner.recovery import (
    FilesystemRecoveryService,
    RecoveryMethod,
    RecoveryRequest,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.carving import CarvingRequest, probe_photorec
from forensic_image_scanner.recovery.tsk.probe import probe_tsk
from forensic_image_scanner.results import SourceMode
from forensic_image_scanner.scoring.ensemble import FALCONSAI_MODEL, AnalysisProfile
from forensic_image_scanner.workflow import (
    OperationMode,
    SourceKind,
    TargetDescriptor,
    WorkflowRequest,
    analysis_request_from_workflow,
    validate_workflow,
)
from forensic_image_scanner.workflow.device_discovery import discover_physical_devices
from forensic_image_scanner.workflow.source_inspection import (
    FORENSIC_IMAGE_EXTENSIONS,
    inspect_directory,
    inspect_forensic_image,
)


class AnalyzePage(QWidget):
    """Primary analysis interface with a read-only guardrail model."""

    navigate_requested = Signal(str)

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self.source_path = self.state.selected_source
        self.output_directory = self.state.output_directory
        self.source_kind = (
            self.state.source_descriptor.kind
            if self.state.source_descriptor is not None
            else SourceKind.DIRECTORY
        )
        self.discovery_worker = None
        self.discovery_thread = None
        self.analysis_worker: AnalysisWorker | None = None
        self.analysis_thread: QThread | None = None
        self.analysis_started_at = 0.0
        self.analysis_counts = {"LOW": 0, "REVIEW": 0, "HIGH": 0, "ERROR": 0}
        self.recovery_inspection = None
        self.recovery_worker: RecoveryWorker | RecoveryExecutionWorker | None = None
        self.recovery_thread: QThread | None = None
        self.tsk_capability = probe_tsk()
        self.photorec_capability = probe_photorec()
        self.state.recovery_available = self.tsk_capability.available
        self.state.carving_available = self.photorec_capability.available
        self._refreshing_models = False
        self._profile_preference = None

        page_layout = QVBoxLayout(self)
        page_layout.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        self.scroll_area = scroll
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        content = QWidget()
        scroll.setWidget(content)
        page_layout.addWidget(scroll)
        root = QVBoxLayout(content)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        title = QLabel("New Operation")
        title.setStyleSheet("color: #edf2f7; font-size: 22px; font-weight: 700;")
        root.addWidget(title)

        source_heading = QLabel("1 · SOURCE")
        source_heading.setStyleSheet("color: #93c5fd; font-weight: 700;")
        root.addWidget(source_heading)

        self.source_kind_group = QButtonGroup(self)
        self.source_kind_group.setExclusive(True)
        self.source_kind_buttons: dict[SourceKind, QPushButton] = {}
        source_types = QHBoxLayout()
        for kind, title_text, detail in (
            (SourceKind.DIRECTORY, "FOLDER", "Existing photos/videos"),
            (SourceKind.FORENSIC_IMAGE, "FORENSIC IMAGE", "RAW / DD / IMG / E01"),
            (SourceKind.PHYSICAL_DEVICE, "PHYSICAL DRIVE", "HDD / SATA SSD / NVMe SSD"),
        ):
            button = QPushButton(f"{title_text}\n{detail}")
            button.setCheckable(True)
            button.setMinimumHeight(58)
            button.setStyleSheet(
                "QPushButton:checked { border: 2px solid #3b82f6; background: #172554; }"
            )
            self.source_kind_group.addButton(button)
            self.source_kind_buttons[kind] = button
            source_types.addWidget(button)
            button.clicked.connect(
                lambda checked=False, selected=kind: self._select_source_kind(selected)
            )
        self.source_kind_buttons[self.source_kind].setChecked(True)
        root.addLayout(source_types)

        form = QFormLayout()
        self.source_edit = QLineEdit(self.source_path)
        self.source_edit.setReadOnly(True)
        self.source_edit.setPlaceholderText("/path/to/evidence")
        self.source_button = QPushButton("BROWSE SOURCE")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_edit)
        source_row.addWidget(self.source_button)
        form.addRow("Location", source_row)

        self.device_combo = QComboBox()
        self.device_combo.setPlaceholderText("Select detected device")
        self.device_combo.currentIndexChanged.connect(self._on_device_selected)
        self.device_combo.hide()
        self.device_label = QLabel("Physical device")
        self.device_label.hide()
        form.addRow(self.device_label, self.device_combo)

        self.source_mode_combo = QComboBox()
        self.source_mode_combo.addItem("Evidence (read-only)", SourceMode.EVIDENCE)
        self.source_mode_combo.addItem("Working copy (moves allowed)", SourceMode.WORKING_COPY)
        current_mode = self.source_mode_combo.findData(self.state.source_mode)
        self.source_mode_combo.setCurrentIndex(max(current_mode, 0))
        self.source_mode_label = QLabel("Directory access")
        form.addRow(self.source_mode_label, self.source_mode_combo)

        self.source_card = QLabel("No source selected")
        self.source_card.setWordWrap(True)
        self.source_card.setStyleSheet(
            "color: #e5e7eb; background: #0f172a; border: 1px solid #334155; "
            "padding: 10px; border-radius: 8px;"
        )
        form.addRow("Source status", self.source_card)

        target_heading = QLabel("2 · TARGET")
        target_heading.setStyleSheet("color: #93c5fd; font-weight: 700;")
        form.addRow(target_heading)

        self.output_edit = QLineEdit(self.output_directory)
        self.output_edit.setReadOnly(True)
        self.output_button = QPushButton("BROWSE TARGET")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_row.addWidget(self.output_button)
        form.addRow("Target", output_row)
        self.target_preview = QLabel(
            "TARGET/\n├── recovered/\n├── findings/\n├── reports/\n└── logs/"
        )
        self.target_preview.setProperty("secondary", True)
        form.addRow("Planned structure", self.target_preview)

        operation_heading = QLabel("3 · OPERATION")
        operation_heading.setStyleSheet("color: #93c5fd; font-weight: 700;")
        form.addRow(operation_heading)
        self.operation_group = QButtonGroup(self)
        self.operation_group.setExclusive(True)
        self.operation_buttons: dict[OperationMode, QPushButton] = {}
        operation_row = QHBoxLayout()
        for operation, label in (
            (OperationMode.RECOVER, "RECOVER MEDIA\nDeleted photos/videos\nNo visual analysis"),
            (
                OperationMode.RECOVER_ANALYZE,
                "RECOVER + ANALYZE\nRecover media, then run visual triage",
            ),
            (OperationMode.ANALYZE, "ANALYZE EXISTING MEDIA\nAnalyze media already present"),
        ):
            button = QPushButton(label)
            button.setCheckable(True)
            button.setMinimumHeight(70)
            button.setStyleSheet(
                "QPushButton:checked { border: 2px solid #3b82f6; background: #172554; }"
            )
            self.operation_group.addButton(button)
            self.operation_buttons[operation] = button
            operation_row.addWidget(button)
            button.clicked.connect(
                lambda checked=False, selected=operation: self._select_operation(selected)
            )
        self.operation_buttons[self.state.operation_mode].setChecked(True)
        form.addRow(operation_row)

        self.model_combo = QComboBox()
        self.model_combo.setPlaceholderText("Select analysis profile")
        form.addRow("Analysis profile", self.model_combo)
        self.detector_summary = QLabel()
        self.detector_summary.setWordWrap(True)
        form.addRow("Detectors", self.detector_summary)

        self.recovery_engine = QLabel()
        self.recovery_engine.setWordWrap(True)
        form.addRow("Recovery engine", self.recovery_engine)
        self.recovery_engine.setText(
            (
                f"The Sleuth Kit · READY · {self.tsk_capability.version}"
                if self.tsk_capability.available
                else "The Sleuth Kit · NOT AVAILABLE · Required: mmls, fsstat, fls, icat"
            )
            + "\n"
            + (
                f"PhotoRec · READY · {self.photorec_capability.version}"
                if self.photorec_capability.available
                else "PhotoRec · NOT AVAILABLE"
            )
        )

        self.filesystem_method = QCheckBox("Filesystem recovery — The Sleuth Kit")
        self.filesystem_method.setChecked(self.tsk_capability.available)
        self.filesystem_method.setEnabled(self.tsk_capability.available)
        self.carving_method = QCheckBox("Raw carving — PhotoRec")
        self.carving_method.setChecked(self.photorec_capability.available)
        self.carving_method.setEnabled(self.photorec_capability.available)
        method_options = QHBoxLayout()
        method_options.addWidget(self.filesystem_method)
        method_options.addWidget(self.carving_method)
        form.addRow("Recovery methods", method_options)
        self.filesystem_method.toggled.connect(self._update_start_state)
        self.carving_method.toggled.connect(self._update_start_state)

        self.recovery_images = QCheckBox("Images")
        self.recovery_images.setChecked(True)
        self.recovery_videos = QCheckBox("Videos")
        self.recovery_videos.setChecked(True)
        self.recovery_reallocated = QCheckBox("Include reallocated entries (low confidence)")
        recovery_options = QHBoxLayout()
        recovery_options.addWidget(self.recovery_images)
        recovery_options.addWidget(self.recovery_videos)
        recovery_options.addWidget(self.recovery_reallocated)
        form.addRow("Recovery media", recovery_options)
        self.recovery_images.toggled.connect(self._update_start_state)
        self.recovery_videos.toggled.connect(self._update_start_state)
        self.volume_widget = QWidget()
        self.volume_layout = QVBoxLayout(self.volume_widget)
        self.volume_layout.setContentsMargins(0, 0, 0, 0)
        self.volume_checks: dict[str, QCheckBox] = {}
        form.addRow("Filesystem volumes", self.volume_widget)

        self.manage_models_button = QPushButton("MANAGE DETECTORS")
        self.manage_models_button.clicked.connect(lambda: self.navigate_requested.emit("models"))
        form.addRow("", self.manage_models_button)

        root.addLayout(form)

        self.workflow_summary = QLabel()
        self.workflow_summary.setWordWrap(True)
        self.workflow_summary.setStyleSheet(
            "color: #e5e7eb; background: #111827; padding: 10px; border-radius: 8px;"
        )
        root.addWidget(self.workflow_summary)

        self.status_label = QLabel("No source selected")
        self.status_label.setProperty("secondary", True)
        root.addWidget(self.status_label)

        self.options = []
        options = QGridLayout()
        for index, label in enumerate(
            [
                "Recursive directories",
                "SHA-256 original files",
                "Skip already processed files",
                "Safe Review Mode",
            ]
        ):
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

        self.discover_button = QPushButton("INSPECT SOURCE")
        self.discover_button.clicked.connect(self.discover_images)
        root.addWidget(self.discover_button)

        self.start_button = QPushButton("START ANALYSIS")
        self.start_button.setEnabled(False)
        self.start_button.setStyleSheet(
            "QPushButton { background: #2563eb; color: #f8fafc; border: none; padding: 12px; "
            "border-radius: 8px; font-weight: 700; } "
            "QPushButton:disabled { background: #374151; color: #9ca3af; }"
        )
        self.start_button.clicked.connect(self._handle_start)
        root.addWidget(self.start_button)

        self.analysis_progress = QProgressBar()
        self.analysis_progress.hide()
        root.addWidget(self.analysis_progress)
        self.cancel_button = QPushButton("CANCEL")
        self.cancel_button.hide()
        self.cancel_button.clicked.connect(self._cancel_analysis)
        root.addWidget(self.cancel_button)
        self.open_recovered_button = QPushButton("OPEN TARGET")
        self.open_recovered_button.hide()
        self.open_recovered_button.clicked.connect(
            lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(self.output_directory))))
        )
        root.addWidget(self.open_recovered_button)
        self.view_pipeline_results_button = QPushButton("VIEW RESULTS")
        self.view_pipeline_results_button.hide()
        self.view_pipeline_results_button.clicked.connect(
            lambda: self.navigate_requested.emit("results")
        )
        root.addWidget(self.view_pipeline_results_button)
        self.pause_button = QPushButton("PAUSE — COMING LATER")
        self.pause_button.setEnabled(False)
        self.pause_button.hide()
        root.addWidget(self.pause_button)

        self.source_button.clicked.connect(self._select_source)
        self.output_button.clicked.connect(self._select_output)
        self.source_mode_combo.currentIndexChanged.connect(self._on_source_mode_changed)
        self.model_combo.currentTextChanged.connect(self._update_start_state)
        self._populate_models()
        self.model_combo.currentIndexChanged.connect(self._on_model_selected)
        self.model_combo.activated.connect(self._remember_profile)
        self.state.model_status_changed.connect(lambda _model_id: self._populate_models())
        self.state.source_changed.connect(lambda _source: self._workflow_changed())
        self.state.target_changed.connect(lambda _target: self._workflow_changed())
        self.state.operation_changed.connect(lambda _operation: self._workflow_changed())
        if self.model_combo.currentIndex() >= 0:
            self._on_model_selected(self.model_combo.currentIndex())
        self._render_source_card()
        self.source_mode_combo.setEnabled(self.source_kind is SourceKind.DIRECTORY)
        self.device_combo.setVisible(self.source_kind is SourceKind.PHYSICAL_DEVICE)
        self.device_label.setVisible(self.source_kind is SourceKind.PHYSICAL_DEVICE)
        self.source_mode_combo.setVisible(self.source_kind is SourceKind.DIRECTORY)
        self.source_mode_label.setVisible(self.source_kind is SourceKind.DIRECTORY)
        self.source_button.setText(
            "REFRESH DEVICES" if self.source_kind is SourceKind.PHYSICAL_DEVICE else "BROWSE SOURCE"
        )
        self._update_start_state()
        QTimer.singleShot(0, lambda: self.scroll_area.verticalScrollBar().setValue(0))

    def _populate_models(self) -> None:
        self._refreshing_models = True
        self.model_combo.clear()
        falconsai = []
        installed_backends = []
        for model in self.model_service.available_models():
            if model.model_id.startswith("nudenet-"):
                if model.installed:
                    installed_backends.append(model.model_id)
                continue
            if model.installed and self.state.model_verification(model.model_id) is True:
                falconsai.append(model.model_id)
        ready = sorted(self.state.backend_ready.intersection(installed_backends))
        for model_id in ready:
            variant = model_id.removeprefix("nudenet-")
            if FALCONSAI_MODEL in falconsai:
                self.model_combo.addItem(
                    f"Combined Detection · {variant}", (AnalysisProfile.COMBINED, variant)
                )
        for model_id in falconsai:
            text = "Falconsai Only" if model_id == FALCONSAI_MODEL else model_id
            self.model_combo.addItem(text, model_id)
        for model_id in ready:
            variant = model_id.removeprefix("nudenet-")
            self.model_combo.addItem(
                f"NudeNet Only · {variant}", (AnalysisProfile.NUDENET, variant)
            )
        if not self.model_combo.count():
            self.model_combo.addItem("No ready detector")
        preferred = next(
            (
                index
                for index in range(self.model_combo.count())
                if self.model_combo.itemData(index) == self._profile_preference
            ),
            0,
        )
        self.model_combo.setCurrentIndex(preferred)
        self._refreshing_models = False
        self._on_model_selected(preferred)
        self._update_start_state()

    def _remember_profile(self, _index: int) -> None:
        self._profile_preference = self.model_combo.currentData()

    def _selected_profile(self) -> tuple[AnalysisProfile, str, str] | None:
        data = self.model_combo.currentData()
        if isinstance(data, str):
            return AnalysisProfile.FALCONSAI, data, DEFAULT_VARIANT
        if isinstance(data, (tuple, list)):
            profile, variant = data
            return AnalysisProfile(profile), FALCONSAI_MODEL, variant
        return None

    def _select_source(self) -> None:
        if self.source_kind is SourceKind.DIRECTORY:
            location = QFileDialog.getExistingDirectory(self, "Select evidence directory")
            if location:
                descriptor = inspect_directory(
                    Path(location), read_only=self.state.source_mode is SourceMode.EVIDENCE
                )
                self._set_source(descriptor)
            return
        if self.source_kind is SourceKind.FORENSIC_IMAGE:
            patterns = " ".join(f"*{extension}" for extension in FORENSIC_IMAGE_EXTENSIONS)
            location, _filter = QFileDialog.getOpenFileName(
                self,
                "Select forensic image candidate",
                "",
                f"Forensic images ({patterns});;All files (*)",
            )
            if location:
                self._set_source(inspect_forensic_image(Path(location)))
            return
        self._discover_devices()

    def _select_source_kind(self, kind: SourceKind) -> None:
        if kind is self.source_kind:
            return
        self.source_kind = kind
        self.source_edit.clear()
        self.source_path = ""
        self.state.source_descriptor = None
        self.source_mode_combo.setEnabled(kind is SourceKind.DIRECTORY)
        self.device_combo.setVisible(kind is SourceKind.PHYSICAL_DEVICE)
        self.device_label.setVisible(kind is SourceKind.PHYSICAL_DEVICE)
        self.source_mode_combo.setVisible(kind is SourceKind.DIRECTORY)
        self.source_mode_label.setVisible(kind is SourceKind.DIRECTORY)
        self.source_button.setText(
            "REFRESH DEVICES" if kind is SourceKind.PHYSICAL_DEVICE else "BROWSE SOURCE"
        )
        if kind is not SourceKind.DIRECTORY:
            evidence_index = self.source_mode_combo.findData(SourceMode.EVIDENCE)
            self.source_mode_combo.setCurrentIndex(evidence_index)
        if kind is SourceKind.PHYSICAL_DEVICE:
            self._discover_devices()
        else:
            self.device_combo.clear()
        self.state.add_audit_event(f"source kind selected: {kind.value}")
        self._render_source_card()
        self._update_start_state()

    def _discover_devices(self) -> None:
        result = discover_physical_devices()
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        for descriptor in result.devices:
            capacity = descriptor.metadata.get("capacity_bytes")
            size = _format_bytes(capacity) if isinstance(capacity, int) else "unknown size"
            self.device_combo.addItem(
                f"{descriptor.location} · {descriptor.display_name} · {size}", descriptor
            )
        self.device_combo.blockSignals(False)
        if result.warning:
            self.status_label.setText(result.warning)
        elif self.device_combo.count():
            self.device_combo.setCurrentIndex(0)
            self._on_device_selected(0)
        else:
            self.status_label.setText("No physical devices were reported by lsblk.")

    def _on_device_selected(self, index: int) -> None:
        descriptor = self.device_combo.itemData(index)
        if self.source_kind is SourceKind.PHYSICAL_DEVICE and descriptor is not None:
            self._set_source(descriptor)

    def _set_source(self, descriptor) -> None:
        self.recovery_inspection = None
        self._clear_volume_options()
        self.source_path = descriptor.location
        self.source_edit.setText(descriptor.location)
        self.state.source_descriptor = descriptor
        self.state.add_audit_event(f"source selected: {descriptor.kind.value}")
        self._render_source_card()
        self._update_start_state()

    def _on_model_selected(self, _index: int) -> None:
        if self._refreshing_models:
            return
        selection = self._selected_profile()
        root = self.model_service.model_root
        nude_installed = any(
            (root / f"nudenet-{variant}" / "manifest.json").is_file()
            for variant in NUDENET_VARIANTS
        )
        if selection is None:
            self.detector_summary.setText(
                "Falconsai · unavailable\nNudeNet · "
                + ("unavailable" if nude_installed else "not installed")
            )
            return
        profile, model_id, variant = selection
        lines = []
        if profile is not AnalysisProfile.NUDENET:
            lines.append("Falconsai · Global NSFW classification · VERIFIED · PARTIAL")
            if self.state.selected_model != model_id:
                self.state.selected_model = model_id
        if profile is not AnalysisProfile.FALCONSAI:
            lines.append(f"NudeNet {variant} · Anatomical nudity detection · READY · EXPERIMENTAL")
        elif not self.state.backend_ready:
            lines.append("NudeNet · unavailable" if nude_installed else "NudeNet · not installed")
        self.detector_summary.setText("\n".join(lines))

    def _on_source_mode_changed(self, _index: int) -> None:
        mode = self.source_mode_combo.currentData()
        if isinstance(mode, SourceMode):
            self.state.source_mode = mode
            if self.source_kind is SourceKind.DIRECTORY and self.source_path:
                self.state.source_descriptor = inspect_directory(
                    Path(self.source_path), read_only=mode is SourceMode.EVIDENCE
                )
            self._validate_source()

    def _select_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select operation target")
        if not directory:
            return
        self.output_directory = directory
        self.state.target_directory = directory
        self.output_edit.setText(directory)
        self.state.add_audit_event("target selected")
        self._validate_output()
        self._update_start_state()

    def _validate_source(self) -> None:
        descriptor = self.state.source_descriptor
        if descriptor is None:
            self.status_label.setText("No source selected")
            return
        if not descriptor.exists:
            self.status_label.setText("Selected source is unavailable.")
            return
        if descriptor.kind is not SourceKind.DIRECTORY:
            self.status_label.setText("Source configured. Recovery execution is unavailable.")
        elif self.state.source_mode is SourceMode.WORKING_COPY:
            self.status_label.setText(
                "Working copy selected — explicit verified moves are allowed after analysis."
            )
        else:
            self.status_label.setText(
                "Evidence source selected — analysis and export preserve originals."
            )

    def _validate_output(self) -> None:
        if not self.output_directory:
            return
        descriptor = self.state.source_descriptor
        source = (
            Path(descriptor.location).resolve()
            if descriptor is not None and descriptor.kind is SourceKind.DIRECTORY
            else None
        )
        output = Path(self.output_directory).resolve()
        if source is not None and output.is_relative_to(source):
            self.status_label.setText("Target cannot be inside the source directory.")
        elif output.exists() and not output.is_dir():
            self.status_label.setText("Target must be a directory.")
        elif not output.exists():
            self.status_label.setText("Target will be created on first use.")

    def _select_operation(self, operation: OperationMode) -> None:
        self.state.operation_mode = operation
        self.state.add_audit_event(f"operation selected: {operation.value}")
        labels = {
            OperationMode.ANALYZE: "START ANALYSIS",
            OperationMode.RECOVER: "START RECOVERY",
            OperationMode.RECOVER_ANALYZE: "START RECOVERY + ANALYSIS",
        }
        self.start_button.setText(labels[operation])
        self._update_start_state()

    def _workflow_changed(self) -> None:
        descriptor = self.state.source_descriptor
        if descriptor is not None:
            self.source_kind = descriptor.kind
            self.source_path = descriptor.location
            self.source_edit.setText(descriptor.location)
            self.source_kind_buttons[descriptor.kind].setChecked(True)
        else:
            self.source_path = ""
            self.source_edit.clear()
        self.output_directory = self.state.target_directory
        self.output_edit.setText(self.output_directory)
        self.operation_buttons[self.state.operation_mode].setChecked(True)
        labels = {
            OperationMode.ANALYZE: "START ANALYSIS",
            OperationMode.RECOVER: "START RECOVERY",
            OperationMode.RECOVER_ANALYZE: "START RECOVERY + ANALYSIS",
        }
        self.start_button.setText(labels[self.state.operation_mode])
        self.source_mode_combo.setEnabled(self.source_kind is SourceKind.DIRECTORY)
        self.device_combo.setVisible(self.source_kind is SourceKind.PHYSICAL_DEVICE)
        self.device_label.setVisible(self.source_kind is SourceKind.PHYSICAL_DEVICE)
        self.source_mode_combo.setVisible(self.source_kind is SourceKind.DIRECTORY)
        self.source_mode_label.setVisible(self.source_kind is SourceKind.DIRECTORY)
        self.source_button.setText(
            "REFRESH DEVICES" if self.source_kind is SourceKind.PHYSICAL_DEVICE else "BROWSE SOURCE"
        )
        self._render_source_card()
        self._update_start_state()

    def _workflow_validation(self):
        descriptor = self.state.source_descriptor
        if descriptor is None or not self.output_directory:
            return None
        return validate_workflow(
            WorkflowRequest(
                descriptor,
                TargetDescriptor(Path(self.output_directory)),
                self.state.operation_mode,
            ),
            tsk_available=self.tsk_capability.available,
            carving_available=self.photorec_capability.available,
            analysis_available=self._selected_profile() is not None,
        )

    def _update_start_state(self) -> None:
        descriptor = self.state.source_descriptor
        source_ok = bool(descriptor is not None and descriptor.exists)
        output_ok = bool(self.output_directory)
        model_ok = (
            True
            if self.state.operation_mode is OperationMode.RECOVER
            else self._selected_profile() is not None
        )
        validation = self._workflow_validation()
        supported = bool(validation is not None and validation.executable)
        recovery_options_ok = True
        if self.state.operation_mode in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
            recovery_options_ok = (
                self.recovery_inspection is not None
                and (self.filesystem_method.isChecked() or self.carving_method.isChecked())
                and any(checkbox.isChecked() for checkbox in self.volume_checks.values())
                and (self.recovery_images.isChecked() or self.recovery_videos.isChecked())
            )
        ready = (
            source_ok
            and output_ok
            and model_ok
            and supported
            and self.state.discovery_completed
            and recovery_options_ok
            and self.analysis_thread is None
        )
        self.start_button.setEnabled(ready)
        self.discover_button.setEnabled(
            bool(
                descriptor is not None
                and descriptor.exists
                and (
                    (
                        descriptor.kind is SourceKind.DIRECTORY
                        and self.state.operation_mode is OperationMode.ANALYZE
                    )
                    or (
                        descriptor.kind is SourceKind.FORENSIC_IMAGE
                        and self.state.operation_mode
                        in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}
                        and (self.tsk_capability.available or self.photorec_capability.available)
                    )
                )
            )
        )
        self._render_workflow_summary(validation)
        if not source_ok:
            self.status_label.setText("Select a valid evidence source.")
        elif not output_ok:
            self.status_label.setText("Select a target directory.")
        elif validation is not None and not validation.executable:
            unsupported = next(
                (
                    finding.message
                    for finding in validation.findings
                    if finding.code == "operation_unsupported"
                ),
                validation.findings[-1].message,
            )
            self.status_label.setText(unsupported)
        elif not model_ok:
            self.status_label.setText("Select an analysis profile with ready detectors.")
        elif not self.state.discovery_completed:
            self.status_label.setText("Inspect the source before starting.")

    def _handle_start(self) -> None:
        if self.state.operation_mode in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
            self._handle_start_recovery()
        else:
            self._handle_start_analysis()

    def _handle_start_analysis(self) -> None:
        if not self.start_button.isEnabled():
            return
        selection = self._selected_profile()
        if selection is None:
            return
        profile, model_id, variant = selection
        descriptor = self.state.source_descriptor
        if descriptor is None:
            return
        workflow = WorkflowRequest(
            descriptor,
            TargetDescriptor(Path(self.output_directory)),
            self.state.operation_mode,
        )
        request = analysis_request_from_workflow(
            workflow,
            model=model_id,
            profile=profile,
            nudenet_variant=variant,
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
        self.state.add_audit_event("workflow execution requested")
        self.state.add_audit_event("analysis started")
        self.state.add_audit_event(f"analysis profile: {profile.value}")
        self.state.add_audit_event(
            f"discovery count: {self.state.discovery_summary.get('total_images', 0)}"
        )
        self.analysis_started_at = time.monotonic()
        self.analysis_counts = {"LOW": 0, "REVIEW": 0, "HIGH": 0, "ERROR": 0}
        self.start_button.setEnabled(False)
        self.status_label.setText("Initializing offline detectors…")
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
        self.state.pipeline_summary = None
        self.state.set_analysis_results(list(summary.results), summary)
        self.state.add_audit_event("analysis results stored")
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
        if self.recovery_worker is not None:
            self.cancel_button.setEnabled(False)
            self.status_label.setText("Cancelling current operation…")
            self.recovery_worker.cancel()
            self.state.add_audit_event("recovery cancelled")
            return
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
        descriptor = self.state.source_descriptor
        if (
            descriptor is not None
            and descriptor.kind is SourceKind.FORENSIC_IMAGE
            and self.state.operation_mode in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}
        ):
            self._inspect_recovery_source()
            return
        if (
            descriptor is None
            or descriptor.kind is not SourceKind.DIRECTORY
            or self.state.operation_mode is not OperationMode.ANALYZE
        ):
            self.status_label.setText("Source inspection is unavailable for this workflow.")
            return
        self.state.analysis_state = "discovering"
        self.status_label.setText("Inspecting directory...")
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

    def _inspect_recovery_source(self) -> None:
        descriptor = self.state.source_descriptor
        if descriptor is None:
            return
        if not self.tsk_capability.available:
            if not self.photorec_capability.available:
                self.status_label.setText("No recovery engine is available.")
                return
            source = Path(descriptor.location)
            volume = RecoveryVolume(
                "volume-01", 0, None, "Whole forensic image", None, False, 512, source.name
            )
            self._recovery_inspection_completed(
                SourceInspection(
                    source,
                    "SINGLE_FILESYSTEM_IMAGE",
                    512,
                    (volume,),
                    "NOT AVAILABLE",
                    ("TSK unavailable; PhotoRec will scan the whole image.",),
                )
            )
            return
        self.status_label.setText("VOLUME INSPECTION")
        self.recovery_thread = QThread(self)
        self.recovery_worker = RecoveryWorker(
            FilesystemRecoveryService(), Path(descriptor.location)
        )
        self.recovery_worker.moveToThread(self.recovery_thread)
        self.recovery_thread.started.connect(self.recovery_worker.run)
        self.recovery_worker.completed.connect(self._recovery_inspection_completed)
        self.recovery_worker.failed.connect(self._recovery_failed)
        self.recovery_worker.finished.connect(self.recovery_worker.deleteLater)
        self.recovery_worker.finished.connect(self.recovery_thread.quit)
        self.recovery_thread.finished.connect(self._recovery_thread_finished)
        self.recovery_thread.start()

    def _recovery_inspection_completed(self, inspection) -> None:
        self.recovery_inspection = inspection
        self._clear_volume_options()
        self.state.discovery_completed = bool(
            inspection.supported_volumes
            or (inspection.volumes and self.photorec_capability.available)
        )
        self.state.add_audit_event("source inspected")
        lines = [
            "SOURCE INSPECTION",
            f"Volume system · {inspection.volume_system}",
            f"Volumes · {len(inspection.volumes)}",
            f"Recoverable filesystems · {len(inspection.supported_volumes)}",
        ]
        for volume in inspection.volumes:
            lines.append(
                f"{volume.volume_id} · {volume.filesystem or 'UNSUPPORTED'} · "
                f"start {volume.start_sector}"
            )
            self.state.add_audit_event("volume detected")
            checkbox = QCheckBox(
                f"{volume.volume_id} — {volume.filesystem or 'unsupported'} — "
                f"start {volume.start_sector}"
            )
            usable = volume.filesystem_detected or self.photorec_capability.available
            checkbox.setChecked(usable)
            checkbox.setEnabled(usable)
            checkbox.toggled.connect(self._update_start_state)
            self.volume_layout.addWidget(checkbox)
            self.volume_checks[volume.volume_id] = checkbox
        self.preview.setText("\n".join(lines))
        self.status_label.setText(
            "Source inspection complete. PhotoRec uses whole-space scanning where "
            "free-space restriction is unavailable."
        )
        self._update_start_state()

    def _handle_start_recovery(self) -> None:
        if not self.start_button.isEnabled() or self.recovery_inspection is None:
            return
        descriptor = self.state.source_descriptor
        if descriptor is None:
            return
        volume_ids = tuple(
            volume_id for volume_id, checkbox in self.volume_checks.items() if checkbox.isChecked()
        )
        filesystem_request = (
            RecoveryRequest(
                Path(descriptor.location),
                Path(self.output_directory),
                volume_ids,
                images=self.recovery_images.isChecked(),
                videos=self.recovery_videos.isChecked(),
                include_reallocated=self.recovery_reallocated.isChecked(),
            )
            if self.filesystem_method.isChecked()
            else None
        )
        carving_request = (
            CarvingRequest(
                Path(descriptor.location),
                Path(self.output_directory),
                volume_ids,
                images=self.recovery_images.isChecked(),
                videos=self.recovery_videos.isChecked(),
            )
            if self.carving_method.isChecked()
            else None
        )
        self.state.add_audit_event("recovery requested")
        if filesystem_request is not None:
            self.state.add_audit_event("TSK backend verified")
        if carving_request is not None:
            self.state.add_audit_event("PhotoRec carving requested")
        self.state.add_audit_event("recovery started")
        self.recovery_thread = QThread(self)
        if self.state.operation_mode is OperationMode.RECOVER_ANALYZE:
            selection = self._selected_profile()
            if selection is None:
                return
            profile, model, variant = selection
            request = PipelineRequest(
                Path(descriptor.location),
                Path(self.output_directory),
                self.model_service.model_root,
                profile=profile,
                model=model,
                variant=variant,
                filesystem=filesystem_request is not None,
                carving=carving_request is not None,
                volume_ids=volume_ids,
                images=self.recovery_images.isChecked(),
                videos=self.recovery_videos.isChecked(),
            )
            self.recovery_worker = PipelineWorker(request, self.recovery_inspection)
        else:
            self.recovery_worker = RecoveryExecutionWorker(
                filesystem_request, carving_request, self.recovery_inspection
            )
        self.recovery_worker.moveToThread(self.recovery_thread)
        self.recovery_thread.started.connect(self.recovery_worker.run)
        self.recovery_worker.progress.connect(self._recovery_progress)
        if self.state.operation_mode is OperationMode.RECOVER_ANALYZE:
            self.recovery_worker.completed.connect(self._pipeline_completed)
        else:
            self.recovery_worker.completed.connect(self._recovery_completed)
        self.recovery_worker.failed.connect(self._recovery_failed)
        self.recovery_worker.finished.connect(self.recovery_worker.deleteLater)
        self.recovery_worker.finished.connect(self.recovery_thread.quit)
        self.recovery_thread.finished.connect(self._recovery_thread_finished)
        self.cancel_button.show()
        self.start_button.setEnabled(False)
        self.recovery_thread.start()

    def _recovery_progress(self, phase: str, current: int, total: int, name: str) -> None:
        self.status_label.setText(f"{phase}\n{current} / {total}\nCurrent\n{name}")

    def _pipeline_completed(self, result) -> None:
        counts = result.summary
        heading = (
            "RECOVERY + ANALYSIS CANCELLED"
            if counts["cancelled"]
            else "RECOVERY + ANALYSIS FINISHED WITH ERRORS"
            if counts["errors"]
            else "RECOVERY + ANALYSIS COMPLETE"
        )
        self.preview.setText(
            heading
            + "\n"
            + "\n".join(
                f"{key.replace('_', ' ').upper()} · {counts[key]}"
                for key in (
                    "recovered",
                    "analyzed_images",
                    "analyzed_videos",
                    "low",
                    "review",
                    "high",
                    "skipped",
                    "errors",
                )
            )
        )
        self.status_label.setText("Sampled video analysis; see pipeline summary for provenance.")
        self.cancel_button.hide()
        self.open_recovered_button.show()
        self.state.pipeline_summary = counts
        self.state.set_analysis_results(
            list(result.analysis.results) if result.analysis is not None else [], result.analysis
        )
        self.view_pipeline_results_button.show()

    def _recovery_completed(self, summary) -> None:
        import json

        self.state.add_audit_event("deleted media enumeration completed")
        self.state.add_audit_event("recovery report written")
        self.state.add_audit_event(
            "recovery cancelled" if summary.cancelled else "recovery completed"
        )
        filesystem_recovered = sum(
            record.method is RecoveryMethod.FILESYSTEM_METADATA
            and record.status is RecoveryStatus.RECOVERED
            for record in summary.records
        )
        carved = sum(
            record.method is RecoveryMethod.FILE_CARVING
            and record.status is RecoveryStatus.RECOVERED
            for record in summary.records
        )
        duplicates = sum(
            record.method is RecoveryMethod.FILE_CARVING
            and getattr(record, "duplicate_of", None) is not None
            for record in summary.records
        )
        catalog_path = summary.target / "reports" / "media_catalog.json"
        counts = {key: 0 for key in ("valid", "partial", "corrupt", "unsupported")}
        if catalog_path.exists():
            with catalog_path.open(encoding="utf-8") as catalog_file:
                for item in json.load(catalog_file)["records"]:
                    counts[item["integrity"]] += 1
        self.preview.setText(
            "RECOVERY COMPLETE\n"
            f"Volumes scanned · {summary.volumes_inspected}\n"
            f"Deleted entries · {summary.deleted_entries}\n"
            f"Media candidates · {summary.media_candidates}\n"
            f"Recovered · {summary.count(RecoveryStatus.RECOVERED)}\n"
            f"Filesystem recovered · {filesystem_recovered}\n"
            f"Carved · {carved}\n"
            f"Duplicates · {duplicates}\n"
            f"Partial · {summary.count(RecoveryStatus.PARTIAL)}\n"
            f"Failed · {summary.count(RecoveryStatus.FAILED)}\n"
            f"Skipped · {summary.count(RecoveryStatus.SKIPPED)}\n"
            "MEDIA VALIDATION\n"
            + "\n".join(f"{key.upper()} · {value}" for key, value in counts.items())
        )
        self.status_label.setText(
            "Recovery cancelled; completed files were preserved and reported."
            if summary.cancelled
            else (
                "Recovery and media validation completed. Methods: "
                + ", ".join(sorted({record.method.value for record in summary.records}))
            )
        )
        self.cancel_button.hide()
        self.open_recovered_button.show()

    def _recovery_failed(self, message: str) -> None:
        self.status_label.setText(f"Recovery unavailable: {message}")
        self.cancel_button.hide()

    def _recovery_thread_finished(self) -> None:
        if self.recovery_thread is not None:
            self.recovery_thread.deleteLater()
        self.recovery_thread = None
        self.recovery_worker = None
        self.cancel_button.setEnabled(True)
        self._update_start_state()

    def _clear_volume_options(self) -> None:
        while self.volume_layout.count():
            item = self.volume_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        self.volume_checks.clear()

    def _on_discovery_completed(self, summary: dict[str, object]) -> None:
        self.state.discovery_summary = summary
        self.state.discovery_completed = True
        self.state.analysis_state = "discovery_complete"
        self.state.add_audit_event("source inspection completed")
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

    def _render_source_card(self) -> None:
        descriptor = self.state.source_descriptor
        if descriptor is None:
            self.source_card.setText("SOURCE\nNo source selected")
            return
        access = (
            "READ ONLY"
            if descriptor.read_only_required or self.state.source_mode is SourceMode.EVIDENCE
            else "WORKING COPY"
        )
        lines = [
            "SOURCE",
            descriptor.display_name,
            descriptor.location,
            f"Type · {descriptor.kind.value.replace('_', ' ').title()}",
            f"Status · {'READY' if descriptor.exists else 'UNAVAILABLE'}",
            f"Access · {access}",
        ]
        if descriptor.kind is SourceKind.FORENSIC_IMAGE:
            candidate = str(descriptor.metadata.get("candidate_format", "unknown")).upper()
            size = descriptor.metadata.get("size_bytes")
            lines.append(f"Candidate format · {candidate} (not verified)")
            lines.append("Inspection · NOT YET INSPECTED")
            if isinstance(size, int):
                lines.append(f"Size · {_format_bytes(size)}")
        if descriptor.kind is SourceKind.PHYSICAL_DEVICE:
            metadata = descriptor.metadata
            device_type = str(metadata.get("device_type", "unknown")).replace("_", " ").upper()
            lines.extend(
                (
                    f"Device type · {device_type}",
                    f"Capacity · {_format_bytes(metadata.get('capacity_bytes'))}",
                    f"Transport · {metadata.get('transport', 'unknown')}",
                    f"Mounted · {'Yes' if metadata.get('mountpoints') else 'No'}",
                    "Raw read permission · "
                    + ("available" if metadata.get("raw_readable") else "unavailable"),
                )
            )
            if device_type in {"SATA SSD", "NVME SSD"}:
                lines.append("Recovery note · TRIM and garbage collection may limit recovery")
        self.source_card.setText("\n".join(lines))

    def _render_workflow_summary(self, validation) -> None:
        descriptor = self.state.source_descriptor
        profile = (
            "Not used for filesystem recovery"
            if self.state.operation_mode is OperationMode.RECOVER
            else self.model_combo.currentText() or "Unavailable"
        )
        source = descriptor.location if descriptor is not None else "Not selected"
        source_type = (
            descriptor.kind.value.replace("_", " ").title()
            if descriptor is not None
            else "Not selected"
        )
        access = "READ ONLY"
        if (
            descriptor is not None
            and descriptor.kind is SourceKind.DIRECTORY
            and self.state.source_mode is SourceMode.WORKING_COPY
        ):
            access = "WORKING COPY"
        operation_labels = {
            OperationMode.ANALYZE: "Analyze existing media",
            OperationMode.RECOVER: "Recover media",
            OperationMode.RECOVER_ANALYZE: "Recover + analyze",
        }
        capability = "NOT CONFIGURED"
        if validation is not None:
            capability = "SUPPORTED" if validation.executable else "NOT YET SUPPORTED"
        recovery_detail = ""
        if self.state.operation_mode in {OperationMode.RECOVER, OperationMode.RECOVER_ANALYZE}:
            media = []
            if self.recovery_images.isChecked():
                media.append("Images")
            if self.recovery_videos.isChecked():
                media.append("Videos")
            methods = []
            if self.filesystem_method.isChecked():
                methods.append("Filesystem metadata recovery")
            if self.carving_method.isChecked():
                methods.append("Raw multimedia carving")
            recovery_detail = (
                f"\nMedia · {' + '.join(media) or 'None'}"
                f"\nMethods · {' + '.join(methods) or 'None'}"
                f"\nTSK · {'READY' if self.tsk_capability.available else 'NOT AVAILABLE'}"
                f"\nPhotoRec · "
                f"{'READY' if self.photorec_capability.available else 'NOT AVAILABLE'}"
            )
        self.workflow_summary.setText(
            "OPERATION SUMMARY\n"
            f"Source · {source}\nSource type · {source_type}\n"
            f"Target · {self.output_directory or 'Not selected'}\n"
            f"Operation · {operation_labels[self.state.operation_mode]}\n"
            f"Analysis profile · {profile}\nSource access · {access}\n"
            f"Execution · {capability}{recovery_detail}"
        )


def _format_bytes(value: object) -> str:
    if not isinstance(value, int):
        return "Unknown"
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1000 or unit == "TB":
            return f"{amount:.1f} {unit}"
        amount /= 1000
    return "Unknown"
