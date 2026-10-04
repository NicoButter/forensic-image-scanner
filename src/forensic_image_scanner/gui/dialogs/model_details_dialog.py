"""Dialog with model metadata and integrity details."""

from __future__ import annotations

from PySide6.QtWidgets import QDialog, QFormLayout, QLabel, QPushButton, QVBoxLayout, QWidget


class ModelDetailsDialog(QDialog):
    """Display verified and local metadata for a selected model."""

    def __init__(self, model_id: str, model_info: dict[str, str], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"Model details: {model_id}")
        self.resize(620, 400)

        layout = QVBoxLayout(self)
        form = QFormLayout()
        for key, value in model_info.items():
            form.addRow(QLabel(key), QLabel(value))
        layout.addLayout(form)

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)
