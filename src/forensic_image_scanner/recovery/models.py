"""Immutable filesystem-recovery records."""

from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType


class MediaKind(StrEnum):
    IMAGE = "image"
    VIDEO = "video"


class RecoveryMethod(StrEnum):
    FILESYSTEM_METADATA = "filesystem_metadata"


class RecoveryStatus(StrEnum):
    RECOVERED = "recovered"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class RecoveryVolume:
    volume_id: str
    start_sector: int
    length_sectors: int | None
    description: str
    filesystem: str | None
    filesystem_detected: bool
    sector_size: int
    source_identifier: str
    label: str | None = None
    partition_slot: str | None = None


@dataclass(frozen=True, slots=True)
class SourceInspection:
    source: Path
    volume_system: str
    sector_size: int
    volumes: tuple[RecoveryVolume, ...]
    tsk_version: str
    diagnostics: tuple[str, ...] = ()

    @property
    def supported_volumes(self) -> tuple[RecoveryVolume, ...]:
        return tuple(volume for volume in self.volumes if volume.filesystem_detected)


@dataclass(frozen=True, slots=True)
class DeletedMediaEntry:
    volume_id: str
    filesystem: str
    metadata_address: str
    original_name: str
    original_path: str | None
    size_bytes: int | None
    modified_time: datetime | None
    accessed_time: datetime | None
    changed_time: datetime | None
    created_time: datetime | None
    extension: str
    media_kind: MediaKind
    reallocated: bool
    orphan: bool
    deleted: bool = True
    file_type: str = "r/r"
    uid: int | None = None
    gid: int | None = None


@dataclass(frozen=True, slots=True)
class RecoveredMedia:
    recovery_id: str
    entry: DeletedMediaEntry
    partition_start_sector: int
    method: RecoveryMethod
    status: RecoveryStatus
    recovered_size: int | None = None
    size_match: bool | None = None
    recovered_relative_path: str | None = None
    recovered_sha256: str | None = None
    error_type: str | None = None
    error_message: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        entry = data.pop("entry")
        data.update(entry)
        for key in ("modified_time", "accessed_time", "changed_time", "created_time"):
            value = data[key]
            data[key] = value.isoformat() if isinstance(value, datetime) else None
        data["method"] = self.method.value
        data["recovery_status"] = self.status.value
        data.pop("status")
        data["candidate_media_kind"] = self.entry.media_kind.value
        data.pop("media_kind")
        data["candidate_extension"] = data.pop("extension")
        data["expected_size"] = data.pop("size_bytes")
        data["recovery_confidence"] = "low" if self.entry.reallocated else "standard"
        return data


@dataclass(frozen=True, slots=True)
class RecoverySessionSummary:
    source: Path
    target: Path
    tsk_version: str
    started_at: datetime
    completed_at: datetime
    volumes_inspected: int
    filesystems_detected: int
    deleted_entries: int
    media_candidates: int
    records: tuple[RecoveredMedia, ...]
    cancelled: bool
    source_sha256: str | None = None
    source_stat_unchanged: bool | None = None
    method: RecoveryMethod = RecoveryMethod.FILESYSTEM_METADATA
    json_path: Path | None = None
    csv_path: Path | None = None
    metadata: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", MappingProxyType(dict(self.metadata)))

    def count(self, status: RecoveryStatus) -> int:
        return sum(record.status is status for record in self.records)
