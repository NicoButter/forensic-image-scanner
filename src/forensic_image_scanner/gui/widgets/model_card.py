"""Functional model card for local model administration."""

from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QGridLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout, QWidget

from forensic_image_scanner.gui.widgets.risk_badge import RiskBadge


class ModelCard(QWidget):
    """Display one audited model and expose permitted administrative actions."""

    download_requested = Signal(str)
    import_requested = Signal(str)
    verify_requested = Signal(str)
    remove_requested = Signal(str)
    details_requested = Signal(str)
    cancel_requested = Signal()

    def __init__(
        self,
        model_id: str,
        status: str,
        provenance: str,
        *,
        title: str | None = None,
        installed: bool = False,
        verified: bool | None = None,
        blocked: bool = False,
        size_text: str = "Not declared",
        license_text: str = "Not declared",
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.model_id = model_id
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        heading = QLabel(title or model_id)
        heading.setStyleSheet("color: #f3f4f6; font-size: 16px; font-weight: 700;")
        layout.addWidget(heading)
        layout.addWidget(RiskBadge("BLOCKED" if blocked else provenance.upper()))

        details = QGridLayout()
        self.status_label = QLabel(status.upper())
        details.addWidget(QLabel("Status"), 0, 0)
        details.addWidget(self.status_label, 0, 1)
        details.addWidget(QLabel("Size"), 1, 0)
        details.addWidget(QLabel(size_text), 1, 1)
        details.addWidget(QLabel("License"), 2, 0)
        details.addWidget(QLabel(license_text), 2, 1)
        if blocked:
            reason = QLabel(
                "Model provenance could not be sufficiently verified.\nInstallation disabled."
            )
            reason.setWordWrap(True)
            details.addWidget(QLabel("Reason"), 3, 0)
            details.addWidget(reason, 3, 1)
        elif installed:
            details.addWidget(QLabel("Integrity"), 3, 0)
            integrity = (
                "UNVERIFIED"
                if verified is None
                else ("VERIFIED" if verified else "INVALID")
            )
            details.addWidget(QLabel(integrity), 3, 1)
        layout.addLayout(details)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)
        self.progress_label = QLabel()
        self.progress_label.hide()
        layout.addWidget(self.progress_label)

        self.download_button = QPushButton("DOWNLOAD AND INSTALL")
        self.import_button = QPushButton("IMPORT LOCAL DIRECTORY")
        self.verify_button = QPushButton("VERIFY INTEGRITY")
        self.remove_button = QPushButton("REMOVE LOCAL MODEL")
        self.details_button = QPushButton("DETAILS")
        self.cancel_button = QPushButton("CANCEL DOWNLOAD")
        self.download_button.setVisible(not installed and not blocked)
        self.import_button.setVisible(not installed and not blocked)
        self.verify_button.setVisible(installed and not blocked)
        self.remove_button.setVisible(installed and not blocked)
        self.cancel_button.hide()

        self.download_button.clicked.connect(lambda: self.download_requested.emit(model_id))
        self.import_button.clicked.connect(lambda: self.import_requested.emit(model_id))
        self.verify_button.clicked.connect(lambda: self.verify_requested.emit(model_id))
        self.remove_button.clicked.connect(lambda: self.remove_requested.emit(model_id))
        self.details_button.clicked.connect(lambda: self.details_requested.emit(model_id))
        self.cancel_button.clicked.connect(self.cancel_requested)
        for button in (
            self.download_button,
            self.import_button,
            self.verify_button,
            self.remove_button,
            self.details_button,
            self.cancel_button,
        ):
            layout.addWidget(button)

    def begin_progress(self, cancellable: bool) -> None:
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.progress_label.setText("Preparing installation…")
        self.progress_label.show()
        self.cancel_button.setVisible(cancellable)
        for button in (
            self.download_button,
            self.import_button,
            self.verify_button,
            self.remove_button,
        ):
            button.setEnabled(False)

    def set_progress(self, received: int, total: int) -> None:
        percent = int(received * 100 / total) if total else 0
        self.progress_bar.setValue(percent)
        self.progress_label.setText(
            f"{received / (1024 * 1024):.1f} MB / {total / (1024 * 1024):.1f} MB"
        )

    def set_phase(self, phase: str) -> None:
        labels = {
            "downloading": "Downloading model",
            "verifying": "Verifying SHA-256…",
            "installing": "Installing atomically…",
        }
        self.progress_label.setText(labels.get(phase, phase))
