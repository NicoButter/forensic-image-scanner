"""Functional local model installation and administration page."""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from PySide6.QtCore import QThread
from PySide6.QtWidgets import QFileDialog, QLabel, QMessageBox, QScrollArea, QVBoxLayout, QWidget

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
        "nudenet-320n": "NudeNet 320n",
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
        title = QLabel("Models")
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
            card.download_requested.connect(self._confirm_download)
            card.import_requested.connect(self._import_directory)
            card.verify_requested.connect(lambda model_id: self._start_worker("verify", model_id))
            card.remove_requested.connect(self._confirm_remove)
            card.details_requested.connect(self._show_details)
            card.cancel_requested.connect(self._cancel_worker)
            self.cards_layout.insertWidget(self.cards_layout.count() - 1, card)
            self.cards[model.model_id] = card

    def _confirm_download(self, model_id: str) -> None:
        manifest = load_reference_manifest(model_id)
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
        self.active_card.begin_progress(cancellable=action == "download")
        if action == "download":
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
        self.state.selected_model = model_id
        self.state.record_model_verification(model_id, True)

    def _operation_cancelled(self) -> None:
        self.state.add_audit_event("Model installation cancelled")

    def _operation_failed(self, message: str) -> None:
        self.state.add_audit_event("Model installation failed")
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
            "Weights license": manifest.weights_license,
            "Primary SHA-256": manifest.sha256,
            "Source": manifest.source,
        }
        ModelDetailsDialog(model_id, details, self).exec()
