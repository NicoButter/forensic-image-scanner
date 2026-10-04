"""Centralized Qt palette and state colors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Palette:
    """Professional dark forensic theme."""

    background = "#0b1020"
    surface = "#111827"
    panel = "#151d2d"
    panel_alt = "#1b2437"
    border = "#2f3b4d"
    border_faint = "#42516a"
    text = "#edf2f7"
    text_muted = "#a9b4c7"
    success = "#2e7d32"
    warning = "#b7791f"
    danger = "#b42318"
    info = "#2563eb"
    accent = "#5b8def"

    @classmethod
    def state_color(cls, state: str) -> str:
        mapping = {
            "VERIFIED": cls.success,
            "PARTIAL": cls.warning,
            "BLOCKED": cls.danger,
            "NOT INSTALLED": cls.text_muted,
            "LOW": cls.success,
            "REVIEW": cls.warning,
            "HIGH": cls.danger,
            "ERROR": cls.danger,
            "OFFLINE": cls.text_muted,
            "READ ONLY": cls.text_muted,
        }
        return mapping.get(state.upper(), cls.info)


PALETTE = Palette()
