"""Append-only local audit records for explicit post-analysis actions."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path


class AuditService:
    """Write concise, non-sensitive transfer events under the report output."""

    def __init__(self, output: str | Path) -> None:
        self.output = Path(output).expanduser().resolve()
        self.path = self.output / "audit.log"

    def record(self, action: str, relative_path: str, detail: str = "") -> None:
        self.output.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(UTC).isoformat()
        suffix = f" | {detail}" if detail else ""
        line = f"{timestamp} | {action} | {relative_path}{suffix}\n"
        # O_APPEND makes each small record a single append operation.  It does
        # not expose image bytes or mutate the selected source.
        descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, line.encode("utf-8"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
