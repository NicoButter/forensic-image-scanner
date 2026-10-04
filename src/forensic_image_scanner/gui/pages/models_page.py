"""Models page wiring the registry into a GUI card list."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QLabel, QWidget

from forensic_image_scanner.gui.services.model_service import ModelService
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.widgets.model_card import ModelCard


class ModelsPage(QWidget):
    """List the audited model set and their verified state."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self.model_service = ModelService()
        self._layout = QGridLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Models")
        title.setStyleSheet("color: #f3f4f6; font-size: 22px; font-weight: 700;")
        self._layout.addWidget(title, 0, 0, 1, 2)

        self.cards: list[ModelCard] = []
        for index, model in enumerate(self.model_service.available_models()):
            card = ModelCard(model.model_id, model.status, model.provenance)
            card.verify_button.clicked.connect(
                lambda checked=False, model_id=model.model_id: self._verify_model(model_id)
            )
            self.cards.append(card)
            self._layout.addWidget(card, index + 1, 0)

    def _verify_model(self, model_id: str) -> None:
        """Verify through the service and publish the result to shared state."""
        self.state.selected_model = model_id
        self.state.record_model_verification(model_id, self.model_service.verify_model(model_id))
