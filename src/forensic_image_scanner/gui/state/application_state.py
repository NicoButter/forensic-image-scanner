"""Observable global state for the desktop application."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.results import SourceMode
from forensic_image_scanner.workflow import (
    OperationMode,
    SourceDescriptor,
    SourceKind,
    TargetDescriptor,
)
from forensic_image_scanner.workflow.validation import capability_for


class ApplicationState(QObject):
    """Central state container and notification boundary for the GUI."""

    selected_page_changed = Signal(str)
    selected_model_changed = Signal(str)
    model_status_changed = Signal(str)
    network_policy_changed = Signal(str)
    audit_event_added = Signal(str)
    analysis_results_changed = Signal()
    source_mode_changed = Signal(str)
    source_changed = Signal(object)
    target_changed = Signal(object)
    operation_changed = Signal(object)
    workflow_capability_changed = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._selected_page = "home"
        self._selected_model = ""
        self._model_verification: dict[str, bool] = {}
        self._model_download_active = False
        self.backend_ready: set[str] = set()
        self._source_descriptor: SourceDescriptor | None = None
        self._target_descriptor: TargetDescriptor | None = None
        self._operation_mode = OperationMode.ANALYZE
        self._source_mode = SourceMode.EVIDENCE
        self.safe_review_mode = True
        self.current_case = "Not available"
        self.analysis_state = "idle"
        self.discovery_completed = False
        self.discovery_summary: dict[str, object] = {}
        self.analysis_results: list[object] = []
        self.analysis_summary: object | None = None
        self.log_messages = ["application started"]

    @property
    def selected_page(self) -> str:
        return self._selected_page

    @selected_page.setter
    def selected_page(self, value: str) -> None:
        if value != self._selected_page:
            self._selected_page = value
            self.selected_page_changed.emit(value)

    @property
    def selected_model(self) -> str:
        return self._selected_model

    @selected_model.setter
    def selected_model(self, value: str) -> None:
        if value != self._selected_model:
            self._selected_model = value
            self.selected_model_changed.emit(value)
            self.model_status_changed.emit(value)

    @property
    def model_download_active(self) -> bool:
        return self._model_download_active

    @model_download_active.setter
    def model_download_active(self, active: bool) -> None:
        active = bool(active)
        if active != self._model_download_active:
            self._model_download_active = active
            self.network_policy_changed.emit(self.network_policy_label)

    @property
    def network_policy_label(self) -> str:
        if self._model_download_active:
            return "MODEL DOWNLOAD"
        return "ANALYSIS OFFLINE"

    @property
    def source_mode(self) -> SourceMode:
        return self._source_mode

    @source_mode.setter
    def source_mode(self, value: SourceMode | str) -> None:
        mode = SourceMode(value)
        if mode is not self._source_mode:
            self._source_mode = mode
            self.source_mode_changed.emit(mode.value)

    @property
    def source_descriptor(self) -> SourceDescriptor | None:
        return self._source_descriptor

    @source_descriptor.setter
    def source_descriptor(self, value: SourceDescriptor | None) -> None:
        if value == self._source_descriptor:
            return
        self._source_descriptor = value
        if value is not None and value.kind is not SourceKind.DIRECTORY:
            self.source_mode = SourceMode.EVIDENCE
        self.discovery_completed = False
        self.discovery_summary = {}
        if self.analysis_state in {"discovering", "discovery_complete"}:
            self.analysis_state = "idle"
        self.source_changed.emit(value)
        self._emit_capability()

    @property
    def selected_source(self) -> str:
        """Compatibility view of the typed source location."""
        return self._source_descriptor.location if self._source_descriptor else ""

    @selected_source.setter
    def selected_source(self, value: str) -> None:
        if not value:
            self.source_descriptor = None
            return
        from forensic_image_scanner.workflow.source_inspection import inspect_directory

        self.source_descriptor = inspect_directory(
            Path(value), read_only=self.source_mode is SourceMode.EVIDENCE
        )

    @property
    def target_directory(self) -> str:
        return str(self._target_descriptor.path) if self._target_descriptor else ""

    @target_directory.setter
    def target_directory(self, value: str) -> None:
        self.target_descriptor = TargetDescriptor(Path(value).expanduser()) if value else None

    @property
    def target_descriptor(self) -> TargetDescriptor | None:
        return self._target_descriptor

    @target_descriptor.setter
    def target_descriptor(self, value: TargetDescriptor | None) -> None:
        if value is not None and not isinstance(value, TargetDescriptor):
            raise TypeError("target must be TargetDescriptor or None")
        if value == self._target_descriptor:
            return
        self._target_descriptor = value
        self.target_changed.emit(value)
        self._emit_capability()

    @property
    def output_directory(self) -> str:
        """Compatibility alias used by reports and export services."""
        return self.target_directory

    @output_directory.setter
    def output_directory(self, value: str) -> None:
        self.target_directory = value

    @property
    def operation_mode(self) -> OperationMode:
        return self._operation_mode

    @operation_mode.setter
    def operation_mode(self, value: OperationMode | str) -> None:
        operation = OperationMode(value)
        if operation is self._operation_mode:
            return
        self._operation_mode = operation
        self.operation_changed.emit(operation)
        self._emit_capability()

    def _emit_capability(self) -> None:
        kind = self._source_descriptor.kind if self._source_descriptor else SourceKind.DIRECTORY
        self.workflow_capability_changed.emit(capability_for(kind, self._operation_mode))

    def model_verification(self, model_id: str) -> bool | None:
        """Return this session's verification result, or None if not checked yet."""
        return self._model_verification.get(model_id)

    def record_model_verification(self, model_id: str, verified: bool) -> None:
        self._model_verification[model_id] = bool(verified)
        self.model_status_changed.emit(model_id)

    def clear_model(self, model_id: str) -> None:
        self._model_verification.pop(model_id, None)
        self.backend_ready.discard(model_id)
        if self.selected_model == model_id:
            self.selected_model = ""
        else:
            self.model_status_changed.emit(model_id)

    def add_audit_event(self, message: str) -> None:
        self.log_messages.append(message)
        self.audit_event_added.emit(message)

    def set_analysis_results(self, results: list[object], summary: object) -> None:
        self.analysis_results = results
        self.analysis_summary = summary
        self.analysis_results_changed.emit()
