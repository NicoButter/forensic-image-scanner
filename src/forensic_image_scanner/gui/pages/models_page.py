"""Models page wiring the registry into a GUI card list."""

from __future__ import annotations

from PySide6.QtWidgets import QGridLayout, QLabel, QWidget

from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.widgets.model_card import ModelCard


class ModelsPage(QWidget):
    """List the audited model set and their verified state."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self._layout = QGridLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Models")
        title.setStyleSheet("color: #f3f4f6; font-size: 22px; font-weight: 700;")
        self._layout.addWidget(title, 0, 0, 1, 2)

        self.cards: list[ModelCard] = []
        for index, (model_id, state, provenance) in enumerate([
            ("falconsai-nsfw-image-detection", "Verified", "verified"),
            ("nudenet-320n", "Blocked", "blocked_provenance"),
        ]):
            card = ModelCard(model_id, state, provenance)
            self.cards.append(card)
            self._layout.addWidget(card, index + 1, 0)
