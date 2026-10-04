"""Results page with a read-only evidence panel."""

from __future__ import annotations

from PySide6.QtWidgets import QHBoxLayout, QLabel, QVBoxLayout, QWidget

from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.widgets.evidence_card import EvidenceCard


class ResultsPage(QWidget):
    """Supports result filtering, thumbnails, and metadata inspection."""

    def __init__(self, state: ApplicationState | None = None, parent=None) -> None:
        super().__init__(parent)
        self.state = state or ApplicationState()
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(20, 20, 20, 20)
        self._layout.setSpacing(16)

        filter_panel = QVBoxLayout()
        filter_panel.addWidget(QLabel("Risk"))
        for label in ("HIGH", "REVIEW", "LOW"):
            filter_panel.addWidget(QLabel(f"☑ {label}"))
        filter_panel.addWidget(QLabel("Score"))
        filter_panel.addWidget(QLabel("[ slider ]"))
        self._layout.addLayout(filter_panel)

        grid_panel = QVBoxLayout()
        grid_panel.addWidget(QLabel("Results grid"))
        grid_panel.addWidget(QLabel("thumbnail preview placeholder"))
        self._layout.addLayout(grid_panel)

        detail_panel = QVBoxLayout()
        detail_panel.addWidget(EvidenceCard("EVIDENCE"))
        detail_panel.addWidget(EvidenceCard("ANALYSIS"))
        detail_panel.addWidget(EvidenceCard("RESULT"))
        self._layout.addLayout(detail_panel)
