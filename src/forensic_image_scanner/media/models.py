"""Catalog types independent of recovery status."""

from dataclasses import asdict, dataclass, field
from enum import StrEnum


class MediaIntegrity(StrEnum):
    VALID = "valid"
    PARTIAL = "partial"
    CORRUPT = "corrupt"
    UNSUPPORTED = "unsupported"


@dataclass
class MediaRecord:
    media_id: str
    sha256: str
    relative_path: str
    size_bytes: int
    media_kind: str
    candidate_extension: str
    actual_format: str | None = None
    integrity: MediaIntegrity = MediaIntegrity.CORRUPT
    width: int | None = None
    height: int | None = None
    duration_seconds: float | None = None
    codec: str | None = None
    frame_rate: float | None = None
    video_stream_count: int | None = None
    recovery_methods: list[str] = field(default_factory=list)
    recovery_ids: list[str] = field(default_factory=list)
    original_paths: list[str] = field(default_factory=list)
    provenance: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
