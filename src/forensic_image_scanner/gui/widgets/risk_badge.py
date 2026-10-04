"""Badge widget for triage risk states."""

from __future__ import annotations

from PySide6.QtWidgets import QLabel


class RiskBadge(QLabel):
    """Context-specific risk badge with neutral forensic colors."""

    def __init__(self, text: str, parent=None) -> None:
        super().__init__(text, parent)
        self.setAlignment(self.alignment())
        self._update_style(text)

    def _update_style(self, text: str) -> None:
        palette = {
            "LOW": "#14532d",
            "REVIEW": "#78350f",
            "HIGH": "#7f1d1d",
            "VERIFIED": "#1d4ed8",
            "PARTIAL": "#92400e",
            "BLOCKED": "#7f1d1d",
            "ERROR": "#7f1d1d",
            "OFFLINE": "#374151",
            "READ ONLY": "#374151",
        }
        color = palette.get(text.upper(), "#374151")
        self.setStyleSheet(
            f"color: #f3f4f6; background-color: {color}; "
            "border: 1px solid #d1d5db; border-radius: 10px; "
            "padding: 4px 8px; font-weight: 700;"
        )
