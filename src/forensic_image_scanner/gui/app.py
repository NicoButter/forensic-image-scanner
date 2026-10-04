"""Application bootstrap for the Qt GUI."""

from __future__ import annotations

import sys
from collections.abc import Sequence


def _require_qt() -> tuple[type, type]:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as exc:  # pragma: no cover - exercised when optional dependency is absent
        msg = (
            "PySide6 is not installed. Install the GUI extra with: "
            "python -m pip install -e \".[gui]\""
        )
        raise RuntimeError(msg) from exc
    return QApplication, QApplication


def create_application(argv: Sequence[str] | None = None) -> object:
    """Create and configure the Qt application instance."""
    QApplication, _ = _require_qt()
    app = QApplication.instance()
    if app is None:
        app = QApplication(list(argv) if argv is not None else sys.argv)
    app.setApplicationName("Forensic Image Scanner")
    app.setOrganizationName("Forensic Image Scanner")
    return app


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the desktop application."""
    from forensic_image_scanner.gui.main_window import MainWindow

    app = create_application(argv)
    window = MainWindow()
    window.show()
    return app.exec()
