"""Observable global state for the desktop application."""

from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from forensic_image_scanner.results import SourceMode


class ApplicationState(QObject):
    """Central state container and notification boundary for the GUI."""

    selected_page_changed = Signal(str)
    selected_model_changed = Signal(str)
    model_status_changed = Signal(str)
    network_policy_changed = Signal(str)
    audit_event_added = Signal(str)
    analysis_results_changed = Signal()
    source_mode_changed = Signal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._selected_page = "home"
        self._selected_model = ""
        self._model_verification: dict[str, bool] = {}
        self._model_download_active = False
        self.selected_source = ""
        self.output_directory = ""
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

    def model_verification(self, model_id: str) -> bool | None:
        """Return this session's verification result, or None if not checked yet."""
        return self._model_verification.get(model_id)

    def record_model_verification(self, model_id: str, verified: bool) -> None:
        self._model_verification[model_id] = bool(verified)
        self.model_status_changed.emit(model_id)

    def clear_model(self, model_id: str) -> None:
        self._model_verification.pop(model_id, None)
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
