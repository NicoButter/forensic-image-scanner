"""Append-only case audit event serialization."""

import json
import os
import stat
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.case.models import AuditEvent

_AUDIT_LOCK = threading.Lock()


def append_event(
    path: Path,
    *,
    case_id: str,
    event: str,
    component: str,
    details: Mapping[str, object] | None = None,
) -> AuditEvent:
    if not event.strip() or not component.strip():
        raise ValueError("audit event and component are required")
    payload = dict(details or {})
    encoded_details = json.dumps(payload, ensure_ascii=False, allow_nan=False)
    if len(encoded_details.encode("utf-8")) > 4096:
        raise ValueError("audit details exceed the allowed size")
    record = AuditEvent(
        datetime.now(UTC).isoformat(),
        case_id,
        event,
        component,
        payload,
    )
    line = (json.dumps(record.to_dict(), ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8"
    )
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    with _AUDIT_LOCK:
        descriptor = os.open(path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("unsafe case audit log")
            offset = 0
            while offset < len(line):
                offset += os.write(descriptor, line[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return record


def read_events(path: Path, case_id: str) -> list[AuditEvent]:
    if path.is_symlink() or not path.is_file():
        raise ValueError("case audit log is missing or unsafe")
    records: list[AuditEvent] = []
    with path.open(encoding="utf-8") as audit_file:
        for line_number, line in enumerate(audit_file, start=1):
            try:
                item = json.loads(line)
                event = AuditEvent(
                    timestamp=item["timestamp"],
                    case_id=item["case_id"],
                    event=item["event"],
                    component=item["component"],
                    details=item["details"],
                )
                datetime.fromisoformat(event.timestamp)
                if (
                    not event.event
                    or not event.component
                    or not isinstance(event.details, dict)
                ):
                    raise ValueError
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError(f"malformed case audit record at line {line_number}") from exc
            if event.case_id != case_id:
                raise ValueError(f"case_id mismatch in audit record at line {line_number}")
            records.append(event)
    return records
