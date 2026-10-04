"""Audit event data model for the GUI log."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class AuditEvent:
    """Small audit event used by ApplicationState and the audit page."""

    timestamp: str
    category: str
    message: str
