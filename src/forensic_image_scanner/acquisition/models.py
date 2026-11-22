"""Typed acquisition requests, safety findings and outcomes."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path


class AcquisitionMethod(StrEnum):
    E01 = "e01"
    RAW = "raw"


class VerificationStatus(StrEnum):
    VERIFIED = "verified"
    FAILED = "failed"
    NOT_PERFORMED = "not_performed"


@dataclass(frozen=True, slots=True)
class SafetyResult:
    allowed: bool
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    source_device: str | None = None
    source_identity: str | None = None
    target_disks: tuple[str, ...] = ()
    model: str | None = None
    serial: str | None = None
    capacity_bytes: int | None = None
    transport: str | None = None


@dataclass(frozen=True, slots=True)
class AcquisitionRequest:
    source: Path
    target: Path
    method: AcquisitionMethod
    resume: bool = False
    case_metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    source: str
    source_identity: str
    model: str | None
    serial: str | None
    capacity_bytes: int | None
    transport: str | None
    method: AcquisitionMethod
    tool: str
    tool_version: str | None
    started_at: datetime
    completed_at: datetime
    output: str
    bytes_acquired: int | None
    sha256: str | None
    verification: VerificationStatus
    completed: bool
    errors: tuple[str, ...]
    cancelled: bool
    mapfile: str | None = None
    case_metadata: dict[str, str] = field(default_factory=dict)
    safety_warnings: tuple[str, ...] = ()
    read_errors: int | None = None
    read_error_bytes: int | None = None
