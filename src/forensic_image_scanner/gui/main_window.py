"""Main desktop window using a fixed sidebar and stacked page layout."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import ClassVar

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QStackedWidget,
    QWidget,
)

from forensic_image_scanner import __version__
from forensic_image_scanner.gui.pages.analyze_page import AnalyzePage
from forensic_image_scanner.gui.pages.audit_page import AuditPage
from forensic_image_scanner.gui.pages.home_page import HomePage
from forensic_image_scanner.gui.pages.models_page import ModelsPage
from forensic_image_scanner.gui.pages.results_page import ResultsPage
from forensic_image_scanner.gui.pages.settings_page import SettingsPage
from forensic_image_scanner.gui.state.application_state import ApplicationState
from forensic_image_scanner.gui.theme.metrics import MIN_HEIGHT, MIN_WIDTH, SIDEBAR_WIDTH, WINDOW_HEIGHT, WINDOW_WIDTH
from forensic_image_scanner.gui.widgets.sidebar import Sidebar
from forensic_image_scanner.gui.widgets.status_bar import StatusBar


class MainWindow(QMainWindow):
    """Desktop shell with a left navigation sidebar and a stacked content area."""

    PAGE_LABELS: ClassVar[tuple[str, ...]] = (
        "Inicio",
        "Analizar",
        "Resultados",
        "Modelos",
        "Auditoría",
        "Configuración",
    )
    PAGE_KEYS: ClassVar[tuple[str, ...]] = (
        "home",
        "analyze",
        "results",
        "models",
        "audit",
        "settings",
    )

    def __init__(self, state: ApplicationState | None = None) -> None:
        super().__init__()
        self.state = state or ApplicationState()
        self._setup_window()
        self._setup_header()
        self._setup_body()
        self._apply_styles()
        self.setCurrentPage("home")

    def _setup_window(self) -> None:
        self.setWindowTitle("Forensic Image Scanner")
        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)
        self.setMinimumSize(MIN_WIDTH, MIN_HEIGHT)

    def _setup_header(self) -> None:
        header = QWidget()
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 12, 20, 12)

        title = QLabel("FORENSIC IMAGE SCANNER")
        title.setStyleSheet(
            "color: #edf2f7; font-size: 20px; font-weight: 700; letter-spacing: 1px;"
        )
        header_layout.addWidget(title)
        header_layout.addStretch(1)

        badge_labels = ("OFFLINE", "MODEL VERIFIED", "READ ONLY")
        for text in badge_labels:
            badge = QPushButton(text)
            badge.setEnabled(False)
            badge.setStyleSheet(
                "QPushButton { background: #111827; color: #edf2f7; border: 1px solid #2f3b4d; "
                "border-radius: 12px; padding: 6px 10px; font-size: 10px; font-weight: 700; }"
            )
            header_layout.addWidget(badge)

        self.setMenuWidget(header)

    def _setup_body(self) -> None:
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)

        self.sidebar = Sidebar(self.PAGE_LABELS, self.PAGE_KEYS)
        self.sidebar.setFixedWidth(SIDEBAR_WIDTH)
        self.sidebar.page_requested.connect(self.setCurrentPage)
        container_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.pages = {
            "home": HomePage(state=self.state),
            "analyze": AnalyzePage(state=self.state),
            "results": ResultsPage(state=self.state),
            "models": ModelsPage(state=self.state),
            "audit": AuditPage(state=self.state),
            "settings": SettingsPage(state=self.state),
        }
        for page in self.pages.values():
            self.stack.addWidget(page)
        container_layout.addWidget(self.stack)
        self.setCentralWidget(container)

        status = StatusBar(scanner_version=__version__)
        status.setStyleSheet("background: #0f172a; border-top: 1px solid #2f3b4d;")
        self.set_status_bar(status)

    def _apply_styles(self) -> None:
        style_path = Path(files("forensic_image_scanner.gui.theme").joinpath("dark.qss"))
        style_sheet = style_path.read_text(encoding="utf-8") if style_path.exists() else ""
        self.setStyleSheet(style_sheet)

    def setCurrentPage(self, page_key: str) -> None:
        if page_key not in self.pages:
            return
        self.state.selected_page = page_key
        self.stack.setCurrentWidget(self.pages[page_key])
        self.sidebar.set_active(page_key)

    def set_status_bar(self, widget: QWidget) -> None:
        bar = self.statusBar()
        bar.clearMessage()
        bar.setStyleSheet("background: #0b1020; color: #edf2f7;")
        bar.addPermanentWidget(widget)
