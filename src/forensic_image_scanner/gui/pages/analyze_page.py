"""Analyze page for evidence source and pre-scan information."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class AnalyzePage(QWidget):
    """Primary analysis interface with a read-only guardrail model."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.source_path = ""
        self.output_directory = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        title = QLabel("Analyze")
        title.setStyleSheet("color: #f3f4f6; font-size: 22px; font-weight: 700;")
        root.addWidget(title)

        form = QFormLayout()
        self.source_edit = QLineEdit()
        self.source_edit.setPlaceholderText("/path/to/evidence")
        self.source_button = QPushButton("Select directory")
        source_row = QHBoxLayout()
        source_row.addWidget(self.source_edit)
        source_row.addWidget(self.source_button)
        form.addRow("Evidence source", source_row)

        self.output_edit = QLineEdit()
        self.output_button = QPushButton("Select output")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_edit)
        output_row.addWidget(self.output_button)
        form.addRow("Report output directory", output_row)

        self.model_combo = QLineEdit()
        self.model_combo.setPlaceholderText("Model registry")
        form.addRow("Model", self.model_combo)

        root.addLayout(form)

        options = QGridLayout()
        for index, label in enumerate([
            "Recursive directories",
            "SHA-256 original files",
            "Skip already processed files",
            "Safe Review Mode",
        ]):
            checkbox = QCheckBox(label)
            checkbox.setChecked(index in (0, 1, 3))
            if index == 3:
                checkbox.setChecked(True)
            options.addWidget(checkbox, index // 2, index % 2)
        root.addLayout(options)

        self.preview = QLabel("Files discovered\n0\n\nTotal size\n0 bytes")
        self.preview.setStyleSheet(
            "color: #f3f4f6; background: #0f172a; border: 1px solid #374151; "
            "padding: 12px; border-radius: 8px;"
        )
        root.addWidget(self.preview)

        self.start_button = QPushButton("START ANALYSIS")
        self.start_button.setEnabled(False)
        self.start_button.setStyleSheet(
            "QPushButton { background: #1d4ed8; color: #f8fafc; border: none; padding: 12px; "
            "border-radius: 8px; font-weight: 700; } "
            "QPushButton:disabled { background: #374151; color: #9ca3af; }"
        )
        root.addWidget(self.start_button)

        self.source_button.clicked.connect(self._select_source)
        self.output_button.clicked.connect(self._select_output)

    def _select_source(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select evidence directory")
        if directory:
            self.source_path = directory
            self.source_edit.setText(directory)
            self._update_start_state()

    def _select_output(self) -> None:
        directory = QFileDialog.getExistingDirectory(self, "Select report output directory")
        if directory:
            self.output_directory = directory
            self.output_edit.setText(directory)
            self._update_start_state()

    def _update_start_state(self) -> None:
        self.start_button.setEnabled(bool(self.source_path) and bool(self.output_directory))
