"""Read-only source description without format-verification claims."""

from contextlib import suppress
from pathlib import Path

from forensic_image_scanner.workflow.models import (
    CandidateImageFormat,
    SourceDescriptor,
    SourceKind,
)

RAW_EXTENSIONS = frozenset({".dd", ".raw", ".img"})
EWF_EXTENSIONS = frozenset({".e01", ".ex01"})
FORENSIC_IMAGE_EXTENSIONS = RAW_EXTENSIONS | EWF_EXTENSIONS


def candidate_image_format(path: Path) -> CandidateImageFormat:
    suffix = path.suffix.casefold()
    if suffix in RAW_EXTENSIONS:
        return CandidateImageFormat.RAW
    if suffix in EWF_EXTENSIONS:
        return CandidateImageFormat.EWF
    return CandidateImageFormat.UNKNOWN


def inspect_directory(path: Path, *, read_only: bool = True) -> SourceDescriptor:
    resolved = path.expanduser().resolve()
    return SourceDescriptor(
        SourceKind.DIRECTORY,
        str(resolved),
        resolved.name or str(resolved),
        resolved.is_dir(),
        read_only,
        {"access": "read_only" if read_only else "working_copy"},
    )


def inspect_forensic_image(path: Path) -> SourceDescriptor:
    resolved = path.expanduser().resolve()
    exists = resolved.is_file()
    metadata: dict[str, object] = {
        "candidate_format": candidate_image_format(resolved).value,
        "format_verified": False,
        "inspection_status": "not_yet_inspected",
    }
    if exists:
        with suppress(OSError):
            metadata["size_bytes"] = resolved.stat().st_size
    return SourceDescriptor(
        SourceKind.FORENSIC_IMAGE,
        str(resolved),
        resolved.name,
        exists,
        True,
        metadata,
    )
