"""Home page for the forensic desktop app."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QGridLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from forensic_image_scanner.gui.services.model_service import ActiveModelStatus, ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState


class HomePage(QWidget):
    """Landing page for triage and workflow navigation."""

    navigate_requested = Signal(str)

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self._layout = QVBoxLayout(self)

        title = QLabel("Forensic Image Scanner")
        title.setStyleSheet("color: #f3f4f6; font-size: 26px; font-weight: 700;")
        self._layout.addWidget(title)

        subtitle = QLabel("Local image content triage\nOffline · Read-only · Auditable")
        subtitle.setStyleSheet("color: #d1d5db; font-size: 13px; line-height: 1.5;")
        self._layout.addWidget(subtitle)

        summary = QGridLayout()
        summary.setColumnStretch(0, 1)
        summary.setColumnStretch(1, 1)

        fields = [
            ("Active model", "Not available"),
            ("Model Registry", "No usable model installed."),
            ("Last case", "Not available"),
            ("Last analysis", "No analysis session created yet."),
        ]
        self.summary_values: dict[str, QLabel] = {}
        for index, (label, value) in enumerate(fields):
            label_widget = QLabel(label)
            value_widget = QLabel(value)
            label_widget.setStyleSheet("color: #9ca3af; font-weight: 600;")
            value_widget.setStyleSheet("color: #f3f4f6;")
            summary.addWidget(label_widget, index, 0)
            summary.addWidget(value_widget, index, 1)
            self.summary_values[label] = value_widget
        self._layout.addLayout(summary)

        actions = QGridLayout()
        destinations = (
            ("New analysis", "analyze"),
            ("Open results", "results"),
            ("Manage models", "models"),
        )
        self.action_buttons: dict[str, QPushButton] = {}
        for index, (button_name, page_key) in enumerate(destinations):
            button = QPushButton(button_name)
            button.setStyleSheet(
                "QPushButton { background: #1f2937; color: #f3f4f6; border: 1px solid #374151; "
                "padding: 10px; border-radius: 8px; }"
            )
            button.clicked.connect(
                lambda checked=False, destination=page_key: self.navigate_requested.emit(
                    destination
                )
            )
            actions.addWidget(button, 0, index)
            self.action_buttons[page_key] = button
        self._layout.addLayout(actions)
        self.state.selected_model_changed.connect(lambda _model_id: self.refresh_summary())
        self.state.model_status_changed.connect(lambda _model_id: self.refresh_summary())
        self.refresh_summary()

    def refresh_summary(self) -> None:
        model_id = self.state.selected_model
        self.summary_values["Active model"].setText(model_id or "Not available")
        status = self.model_service.active_model_status(
            model_id, self.state.model_verification(model_id)
        )
        registry_text = (
            "Active model verified and usable."
            if status is ActiveModelStatus.VERIFIED
            else "No usable active model."
        )
        self.summary_values["Model Registry"].setText(registry_text)
