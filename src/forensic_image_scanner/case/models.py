"""Typed values persisted by a forensic case."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum


class CaseStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


@dataclass(frozen=True, slots=True)
class CaseMetadata:
    case_id: str
    case_number: str | None
    title: str | None
    description: str | None
    examiner: str | None
    organization: str | None
    evidence_number: str | None
    notes: str | None
    created_at: str
    updated_at: str
    status: CaseStatus

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> CaseMetadata:
        try:
            return cls(
                case_id=str(data["case_id"]),
                case_number=_optional_string(data["case_number"]),
                title=_optional_string(data["title"]),
                description=_optional_string(data["description"]),
                examiner=_optional_string(data["examiner"]),
                organization=_optional_string(data["organization"]),
                evidence_number=_optional_string(data["evidence_number"]),
                notes=_optional_string(data["notes"]),
                created_at=str(data["created_at"]),
                updated_at=str(data["updated_at"]),
                status=CaseStatus(data["status"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid case metadata") from exc


@dataclass(frozen=True, slots=True)
class SourceSummary:
    source_id: str
    source_kind: str
    original_location: str
    model: str | None = None
    serial: str | None = None
    capacity: int | None = None
    transport: str | None = None
    sha256: str | None = None
    acquisition_method: str | None = None
    acquired_image: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    timestamp: str
    case_id: str
    event: str
    component: str
    details: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError("case metadata values must be strings or null")
    return value
