"""Global state for the desktop application."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class ApplicationState:
    """Central state container for the GUI."""

    selected_page: str = "home"
    selected_source: str = ""
    output_directory: str = ""
    selected_model: str = ""
    safe_review_mode: bool = True
    current_case: str = "Not available"
    analysis_state: str = "idle"
    discovery_completed: bool = False
    discovery_summary: dict[str, object] = field(default_factory=dict)
    log_messages: list[str] = field(default_factory=lambda: ["application started"])
