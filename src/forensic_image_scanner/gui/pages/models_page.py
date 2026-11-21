"""Functional local model installation and administration page."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from PySide6.QtCore import QThread, QTimer, QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QFileDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from forensic_image_scanner.detectors.nudenet import (
    NUDENET_VARIANTS,
    backend_disabled,
    runtime_directory,
    runtime_python,
    set_backend_enabled,
)
from forensic_image_scanner.gui.dialogs.model_details_dialog import ModelDetailsDialog
from forensic_image_scanner.gui.services.model_service import ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.widgets.model_card import ModelCard
from forensic_image_scanner.gui.workers.model_installation_worker import ModelInstallationWorker
from forensic_image_scanner.models.installation import ModelInstallationService
from forensic_image_scanner.models.references import load_reference_manifest


class ModelsPage(QWidget):
    """Install, import, verify, inspect, and remove audited local models."""

    DISPLAY_NAMES: ClassVar[dict[str, str]] = {
        "falconsai-nsfw-image-detection": "Falconsai NSFW Image Detection",
        "nudenet-320n": "NudeNet Anatomical Detector · 320n",
        "nudenet-640m": "NudeNet Anatomical Detector · 640m",
    }

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self.installation_service = ModelInstallationService(self.model_service.model_root)
        self.thread: QThread | None = None
        self.worker: ModelInstallationWorker | None = None
        self.active_card: ModelCard | None = None
        self.active_action = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        title = QLabel("Models & Detectors")
        title.setStyleSheet("color: #f3f4f6; font-size: 22px; font-weight: 700;")
        root.addWidget(title)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        self.cards_widget = QWidget()
        self.cards_layout = QVBoxLayout(self.cards_widget)
        self.cards_layout.addStretch(1)
        scroll.setWidget(self.cards_widget)
        root.addWidget(scroll)
        self.cards: dict[str, ModelCard] = {}
        self.state.model_status_changed.connect(lambda _model_id: self.refresh())
        self.refresh()
        model_root = self.model_service.model_root
        self._initial_backends = [
            f"nudenet-{variant}"
            for variant in NUDENET_VARIANTS
            if (model_root / f"nudenet-{variant}" / "manifest.json").is_file()
            and runtime_python(runtime_directory(model_root) / "env").is_file()
            and not backend_disabled(model_root, variant)
        ]
        if self._initial_backends:
            QTimer.singleShot(0, self._check_next_backend)

    def _check_next_backend(self) -> None:
        if self._initial_backends and self.thread is None:
            self._start_worker("check-backend", self._initial_backends.pop(0))

    def refresh(self) -> None:
        while self.cards_layout.count() > 1:
            item = self.cards_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()
        self.cards.clear()
        for model in self.model_service.available_models():
            manifest = load_reference_manifest(model.model_id)
            blocked = manifest.provenance_status.is_blocked
            size = manifest.size_bytes or 0
            card = ModelCard(
                model.model_id,
                "Installed" if model.installed else "Not installed",
                manifest.provenance_status.value,
                title=self.DISPLAY_NAMES.get(model.model_id, model.model_id),
                installed=model.installed,
                verified=self.state.model_verification(model.model_id),
                blocked=blocked,
                size_text=f"~{size / (1024 * 1024):.0f} MB",
                license_text=f"{manifest.weights_license.split(' declared')[0]} declared",
            )
            if manifest.operational_status == "experimental":
                self._configure_backend_card(card, model.installed)
            else:
                card.layout().addWidget(QLabel("Purpose · Global image classification"))
            card.download_requested.connect(self._confirm_download)
            card.import_requested.connect(self._import_directory)
            card.verify_requested.connect(self._verify_card)
            card.remove_requested.connect(self._confirm_remove)
            card.details_requested.connect(self._show_details)
            card.cancel_requested.connect(self._cancel_worker)
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
            self.cards[model.model_id] = card

    def _configure_backend_card(self, card: ModelCard, installed: bool) -> None:
        model_id = card.model_id
        variant = model_id.removeprefix("nudenet-")
        root = self.model_service.model_root
        disabled = backend_disabled(root, variant)
        ready = model_id in self.state.backend_ready and not disabled
        available = installed and runtime_python(runtime_directory(root) / "env").is_file()
        if ready:
            status = "READY"
        elif disabled and available:
            status = "DISABLED"
        else:
            status = "CHECK REQUIRED" if available else "NOT INSTALLED"
        card.status_label.setText(status)
        card.layout().addWidget(QLabel("Experimental · GNU AGPL-3.0 · Training provenance partial"))
        card.download_button.setText("INSTALL BACKEND")
        card.download_button.setVisible(not available)
        card.import_button.hide()
        card.verify_button.setText("VERIFY & CHECK BACKEND")
        card.verify_button.setVisible(available and not disabled)
        if installed:
            location = QPushButton("OPEN LOCATION")
            location.clicked.connect(
                lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(root / model_id)))
            )
            card.layout().addWidget(location)
        if available:
            toggle = QPushButton("ENABLE FOR PROFILES" if disabled else "DISABLE")
            toggle.clicked.connect(lambda: self._toggle_backend(model_id, enabled=disabled))
            card.layout().addWidget(toggle)

    def _toggle_backend(self, model_id: str, *, enabled: bool) -> None:
        if self.thread is not None:
            return
        if enabled:
            self._start_worker("enable-backend", model_id)
            return
        try:
            set_backend_enabled(
                self.model_service.model_root, model_id.removeprefix("nudenet-"), False
            )
        except OSError as exc:
            QMessageBox.critical(self, "Unable to disable backend", str(exc))
            return
        self.state.backend_ready.discard(model_id)
        self.state.model_status_changed.emit(model_id)

    def _verify_card(self, model_id: str) -> None:
        action = "check-backend" if model_id.startswith("nudenet-") else "verify"
        self._start_worker(action, model_id)

    def _confirm_download(self, model_id: str) -> None:
        manifest = load_reference_manifest(model_id)
        if manifest.operational_status == "experimental":
            self._confirm_backend_install(model_id)
            return
        size = (manifest.size_bytes or 0) + sum(
            artifact.size_bytes for artifact in manifest.artifacts
        )
        message = QMessageBox(self)
        message.setWindowTitle("Install model")
        message.setIcon(QMessageBox.Icon.Question)
        message.setText(self.DISPLAY_NAMES.get(model_id, model_id))
        message.setInformativeText(
            f"Size: ~{size / (1024 * 1024):.0f} MB\n\n"
            f"Source: Hugging Face\nRevision: {manifest.source_revision}\n\n"
            f"Declared weights license: {manifest.weights_license}\n"
            f"Training-data provenance: {manifest.provenance_status.value.title()}\n\n"
            "The model will be downloaded and cryptographically verified.\n"
            "Analysis will remain offline after installation."
        )
        message.setStandardButtons(
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ok
        )
        message.button(QMessageBox.StandardButton.Ok).setText("DOWNLOAD")
        if message.exec() == QMessageBox.StandardButton.Ok:
            self.state.add_audit_event("Model installation requested")
            self._start_worker("download", model_id)

    def _confirm_backend_install(self, model_id: str) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Install optional backend")
        dialog.setIcon(QMessageBox.Icon.Question)
        dialog.setText(self.DISPLAY_NAMES[model_id])
        dialog.setInformativeText(
            "License · GNU AGPL-3.0\nStatus · Experimental\n"
            "Training-data provenance · Partially documented\n\n"
            "Install NudeNet and its runtime in a separate local environment."
        )
        dialog.setStandardButtons(QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Ok)
        dialog.button(QMessageBox.StandardButton.Ok).setText("INSTALL")
        if dialog.exec() == QMessageBox.StandardButton.Ok:
            self.state.add_audit_event(f"Optional backend installation approved: {model_id}")
            self._start_worker("install-backend", model_id)

    def _import_directory(self, model_id: str) -> None:
        directory = QFileDialog.getExistingDirectory(
            self, "Select directory containing all declared model artifacts"
        )
        if directory:
            self.state.add_audit_event("Model installation requested")
            self._start_worker("import", model_id, Path(directory))

    def _start_worker(self, action: str, model_id: str, source: Path | None = None) -> None:
        if self.thread is not None:
            return
        self.active_action = action
        self.active_card = self.cards[model_id]
        self.active_card.begin_progress(cancellable=action in {"download", "install-backend"})
        if action in {"download", "install-backend"}:
            self.state.model_download_active = True
        self.thread = QThread(self)
        self.worker = ModelInstallationWorker(self.installation_service, action, model_id, source)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.active_card.set_progress)
        self.worker.phase_changed.connect(self.active_card.set_phase)
        self.worker.completed.connect(self._operation_completed)
        self.worker.cancelled.connect(self._operation_cancelled)
        self.worker.failed.connect(self._operation_failed)
        self.worker.finished.connect(self.worker.deleteLater)
        self.worker.finished.connect(self.thread.quit)
        self.thread.finished.connect(self._thread_finished)
        self.thread.start()

    def _cancel_worker(self) -> None:
        if self.worker is not None:
            self.worker.cancel()

    def _operation_completed(self, model_id: str) -> None:
        if self.active_action == "download":
            self.state.add_audit_event("Model downloaded")
        self.state.add_audit_event("Model integrity verified")
        if self.active_action in {"download", "import"}:
            self.state.add_audit_event("Model installed")
        if model_id.startswith("nudenet-"):
            self.state.backend_ready.add(model_id)
        else:
            self.state.selected_model = model_id
        self.state.record_model_verification(model_id, True)

    def _operation_cancelled(self) -> None:
        self.state.add_audit_event("Model installation cancelled")

    def _operation_failed(self, message: str) -> None:
        self.state.add_audit_event("Model installation failed")
        if self.active_card and self.active_card.model_id.startswith("nudenet-"):
            model_id = self.active_card.model_id
            self.state.backend_ready.discard(model_id)
            self.state.model_status_changed.emit(model_id)
        if self.active_action != "check-backend":
            QMessageBox.critical(self, "Model operation failed", message)

    def _thread_finished(self) -> None:
        self.state.model_download_active = False
        if self.thread is not None:
            self.thread.deleteLater()
        self.worker = None
        self.thread = None
        self.active_card = None
        self.active_action = ""
        self.refresh()
        self._check_next_backend()

    def _confirm_remove(self, model_id: str) -> None:
        answer = QMessageBox.question(
            self,
            "Remove local model?",
            "Only the locally installed model files will be removed.\n\n"
            "Evidence and analysis reports are not affected.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            self.installation_service.remove(model_id)
        except Exception as exc:
            QMessageBox.critical(self, "Unable to remove model", str(exc))
            return
        self.state.clear_model(model_id)
        self.state.add_audit_event("Model removed")
        self.refresh()

    def _show_details(self, model_id: str) -> None:
        manifest = load_reference_manifest(model_id)
        details = {
            "Model ID": manifest.model_id,
            "Revision": manifest.source_revision,
            "Provenance": manifest.provenance_status.value,
            "Code license": manifest.code_license,
            "Weights license": manifest.weights_license,
            "Operational status": manifest.operational_status or "Standard",
            "Primary SHA-256": manifest.sha256,
            "Source": manifest.source,
        }
        ModelDetailsDialog(model_id, details, self).exec()
