"""Model card widget for the model registry view."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget

from forensic_image_scanner.gui.widgets.risk_badge import RiskBadge


class ModelCard(QWidget):
    """Compact visual card for one model entry."""

    def __init__(self, model_id: str, status: str, provenance: str, parent=None) -> None:
        super().__init__(parent)
        self.model_id = model_id
        self._layout = QVBoxLayout(self)
        self._layout.setSpacing(8)

        title = QLabel(model_id)
        title.setStyleSheet("color: #f3f4f6; font-size: 14px; font-weight: 600;")
        self._layout.addWidget(title)

        self._layout.addWidget(RiskBadge(status.upper()))

        info = QLabel(f"Provenance: {provenance}")
        info.setStyleSheet("color: #d1d5db;")
        self._layout.addWidget(info)

        self.verify_button = QPushButton("VERIFY INTEGRITY")
        self.verify_button.setEnabled(status != "Blocked")
        self._layout.addWidget(self.verify_button)
