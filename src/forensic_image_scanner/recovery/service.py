"""Filesystem-aware deleted-media recovery orchestration."""

import errno
import json
import os
import re
import shutil
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePath

from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.recovery.models import (
    DeletedMediaEntry,
    MediaKind,
    RecoveredMedia,
    RecoveryMethod,
    RecoverySessionSummary,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.reports import write_recovery_reports
from forensic_image_scanner.recovery.tsk.backend import TskBackend
from forensic_image_scanner.recovery.tsk.runner import TskCommandError

MIN_FREE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RecoveryRequest:
    source: Path
    target: Path
    volume_ids: tuple[str, ...] = ()
    images: bool = True
    videos: bool = True
    include_reallocated: bool = False
    source_sha256: str | None = None

    def validate(self) -> None:
        source = self.source.expanduser().resolve()
        target = self.target.expanduser().resolve()
        if not source.is_file():
            raise ValueError("source must be a readable forensic image")
        if not self.images and not self.videos:
            raise ValueError("select images, videos, or both")
        if target.exists() and not target.is_dir():
            raise NotADirectoryError(target)
        if target in {source, source.parent}:
            raise ValueError("target must be separate from the source image")


class FilesystemRecoveryService:
    def __init__(self, backend: TskBackend | None = None) -> None:
        self.backend = backend or TskBackend()
        self.enumeration_errors: list[dict[str, str]] = []

    def inspect_source(self, source: Path) -> SourceInspection:
        return self.backend.inspect(source.expanduser().resolve())

    def enumerate_deleted_media(
        self, inspection: SourceInspection, volume_ids: tuple[str, ...] = ()
    ) -> tuple[tuple[DeletedMediaEntry, ...], int]:
        selected = set(volume_ids)
        known = {volume.volume_id for volume in inspection.supported_volumes}
        missing = selected - known
        if missing:
            raise ValueError(f"unknown or unsupported volume: {', '.join(sorted(missing))}")
        self.enumeration_errors = []
        entries: list[DeletedMediaEntry] = []
        deleted_count = 0
        for volume in inspection.supported_volumes:
            if selected and volume.volume_id not in selected:
                continue
            try:
                candidates, volume_deleted_count = self.backend.enumerate_deleted(
                    inspection.source, volume
                )
            except TskCommandError as exc:
                self.enumeration_errors.append(
                    {"volume_id": volume.volume_id, "error_type": exc.code, "message": str(exc)}
                )
                continue
            deleted_count += volume_deleted_count
            entries.extend(candidates)
        return tuple(entries), deleted_count

    def recover(
        self,
        request: RecoveryRequest,
        *,
        inspection: SourceInspection | None = None,
        cancel: threading.Event | None = None,
        progress: Callable[[str, int, int, str], None] | None = None,
        write_reports: bool = True,
    ) -> RecoverySessionSummary:
        request.validate()
        cancel = cancel or threading.Event()
        source = request.source.expanduser().resolve()
        target = request.target.expanduser().resolve()
        for existing in (
            target / "reports" / "recovery.json",
            target / "reports" / "recovery.csv",
            target / "logs" / "recovery.log",
        ):
            if existing.exists():
                raise FileExistsError(f"recovery session output already exists: {existing}")
        before = source.stat()
        started = datetime.now(UTC)
        inspection = inspection or self.inspect_source(source)
        if not inspection.supported_volumes:
            raise TskCommandError("FILESYSTEM_UNSUPPORTED", "no supported filesystem was detected")
        entries, deleted_count = self.enumerate_deleted_media(inspection, request.volume_ids)
        entries = tuple(
            entry
            for entry in entries
            if (entry.media_kind is MediaKind.IMAGE and request.images)
            or (entry.media_kind is MediaKind.VIDEO and request.videos)
        )
        target.mkdir(parents=True, exist_ok=True)
        temporary_root = target / ".fis-tmp"
        temporary_root.mkdir(exist_ok=True)
        records: list[RecoveredMedia] = []
        volumes = {volume.volume_id: volume for volume in inspection.volumes}
        fatal_target_full = False
        try:
            for index, entry in enumerate(entries, 1):
                if cancel.is_set():
                    break
                if progress:
                    progress("RECOVERING", index, len(entries), entry.original_name)
                volume = volumes[entry.volume_id]
                recovery_id = _recovery_id(entry)
                if entry.reallocated and not request.include_reallocated:
                    records.append(
                        _record(
                            entry,
                            volume,
                            recovery_id,
                            RecoveryStatus.SKIPPED,
                            error_type="REALLOCATED",
                            error_message="skipped by default",
                        )
                    )
                    continue
                if shutil.disk_usage(target).free < MIN_FREE_BYTES:
                    fatal_target_full = True
                    records.append(
                        _record(
                            entry,
                            volume,
                            recovery_id,
                            RecoveryStatus.FAILED,
                            error_type="FAILED_TARGET_FULL",
                            error_message="target free space safety threshold reached",
                        )
                    )
                    break
                temporary = temporary_root / f"{recovery_id}.part"
                try:
                    self.backend.extract(source, volume, entry, temporary, cancel)
                    recovered_size = temporary.stat().st_size
                    if recovered_size == 0:
                        raise TskCommandError("EMPTY_OUTPUT", "icat produced zero bytes")
                    digest = sha256_file(temporary)
                    destination = _destination(target, volume, entry, recovery_id, digest)
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    os.replace(temporary, destination)
                    size_match = (
                        recovered_size == entry.size_bytes if entry.size_bytes is not None else None
                    )
                    status = (
                        RecoveryStatus.PARTIAL if size_match is False else RecoveryStatus.RECOVERED
                    )
                    records.append(
                        _record(
                            entry,
                            volume,
                            recovery_id,
                            status,
                            recovered_size=recovered_size,
                            size_match=size_match,
                            relative=str(destination.relative_to(target)),
                            digest=digest,
                            error_type="SIZE_MISMATCH" if size_match is False else None,
                            error_message=(
                                "recovered byte count differs from filesystem metadata"
                                if size_match is False
                                else None
                            ),
                        )
                    )
                except TskCommandError as exc:
                    temporary.unlink(missing_ok=True)
                    if exc.code == "CANCELLED":
                        cancel.set()
                        break
                    records.append(
                        _record(
                            entry,
                            volume,
                            recovery_id,
                            RecoveryStatus.FAILED,
                            error_type=exc.code,
                            error_message=str(exc),
                        )
                    )
                except OSError as exc:
                    temporary.unlink(missing_ok=True)
                    code = "FAILED_TARGET_FULL" if exc.errno == errno.ENOSPC else "RECOVERY_FAILED"
                    records.append(
                        _record(
                            entry,
                            volume,
                            recovery_id,
                            RecoveryStatus.FAILED,
                            error_type=code,
                            error_message=str(exc),
                        )
                    )
                    if exc.errno == errno.ENOSPC:
                        fatal_target_full = True
                        break
        finally:
            for temporary in temporary_root.glob("*.part"):
                temporary.unlink(missing_ok=True)
            with suppress(OSError):
                temporary_root.rmdir()
        after = source.stat()
        summary = RecoverySessionSummary(
            source,
            target,
            inspection.tsk_version,
            started,
            datetime.now(UTC),
            len(inspection.volumes),
            len(inspection.supported_volumes),
            deleted_count,
            len(entries),
            tuple(records),
            cancel.is_set(),
            request.source_sha256,
            (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
            metadata={
                "target_full": fatal_target_full,
                "volume_system": inspection.volume_system,
                "sector_size": inspection.sector_size,
                "source_stat_before": {
                    "size_bytes": before.st_size,
                    "mtime_ns": before.st_mtime_ns,
                },
                "source_stat_after": {
                    "size_bytes": after.st_size,
                    "mtime_ns": after.st_mtime_ns,
                },
                "volumes": tuple(
                    {
                        "volume_id": volume.volume_id,
                        "partition_slot": volume.partition_slot,
                        "start_sector": volume.start_sector,
                        "length_sectors": volume.length_sectors,
                        "description": volume.description,
                        "filesystem": volume.filesystem,
                        "label": volume.label,
                        "filesystem_detected": volume.filesystem_detected,
                    }
                    for volume in inspection.volumes
                ),
                "enumeration_errors": tuple(self.enumeration_errors),
            },
        )
        if write_reports:
            json_path, csv_path = write_recovery_reports(summary)
            _write_recovery_log(summary, inspection, tuple(getattr(self.backend, "events", ())))
            return replace(summary, json_path=json_path, csv_path=csv_path)
        return summary


def _recovery_id(entry: DeletedMediaEntry) -> str:
    metadata = re.sub(r"[^A-Za-z0-9_.-]+", "_", entry.metadata_address).strip("_") or "unknown"
    return f"{entry.volume_id}_{metadata}"


def _safe_name(name: str, limit: int = 120) -> str:
    leaf = PurePath(name.replace("\\", "/")).name
    cleaned = re.sub(r"[\x00-\x1f\x7f<>:\"/\\|?*]+", "_", leaf)
    cleaned = re.sub(r"\s+", " ", cleaned).strip(" .") or "unnamed"
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    if PurePath(cleaned).stem.upper() in reserved:
        cleaned = f"_{cleaned}"
    suffix = PurePath(cleaned).suffix[:16]
    stem_limit = max(1, limit - len(suffix))
    return f"{PurePath(cleaned).stem[:stem_limit]}{suffix}"


def _destination(
    target: Path, volume: RecoveryVolume, entry: DeletedMediaEntry, recovery_id: str, digest: str
) -> Path:
    category = "images" if entry.media_kind is MediaKind.IMAGE else "videos"
    directory = target / "recovered" / "filesystem" / volume.volume_id / category
    name = f"rec_{recovery_id}_{_safe_name(entry.original_name)}"
    candidate = directory / name
    if candidate.exists():
        if sha256_file(candidate) == digest:
            candidate = directory / f"{candidate.stem}_{digest[:12]}{candidate.suffix}"
        counter = 2
        while candidate.exists():
            candidate = directory / f"{Path(name).stem}_{counter}{Path(name).suffix}"
            counter += 1
    resolved = candidate.resolve()
    if not resolved.is_relative_to(target.resolve()):
        raise ValueError("recovery destination escaped target")
    return resolved


def _record(
    entry: DeletedMediaEntry,
    volume: RecoveryVolume,
    recovery_id: str,
    status: RecoveryStatus,
    *,
    recovered_size: int | None = None,
    size_match: bool | None = None,
    relative: str | None = None,
    digest: str | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
) -> RecoveredMedia:
    return RecoveredMedia(
        recovery_id,
        entry,
        volume.start_sector,
        RecoveryMethod.FILESYSTEM_METADATA,
        status,
        recovered_size,
        size_match,
        relative,
        digest,
        error_type,
        error_message,
    )


def _write_recovery_log(
    summary: RecoverySessionSummary,
    inspection: SourceInspection,
    backend_events: tuple[dict[str, object], ...],
) -> None:
    logs = summary.target / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    destination = logs / "recovery.log"
    if destination.exists():
        raise FileExistsError("a recovery log already exists in this target")
    entries: list[dict[str, object]] = [
        {
            "event": "session",
            "tsk_version": summary.tsk_version,
            "source_identifier": summary.source.name,
            "volume_system": inspection.volume_system,
            "sector_size": inspection.sector_size,
            "commands": ["mmls", "fsstat", "fls", "icat"],
        }
    ]
    entries.extend(
        {
            "event": "volume",
            "volume_id": volume.volume_id,
            "offset_sectors": volume.start_sector,
            "filesystem": volume.filesystem,
            "supported": volume.filesystem_detected,
        }
        for volume in inspection.volumes
    )
    entries.extend(
        {
            "event": "recovery",
            "recovery_id": record.recovery_id,
            "status": record.status.value,
            "error_type": record.error_type,
            "error_message": record.error_message,
        }
        for record in summary.records
    )
    entries.extend(
        {
            "event": "tsk_command",
            **{
                key: (
                    tuple(str(value).replace(str(summary.source), "<SOURCE>") for value in item)
                    if key == "arguments" and isinstance(item, tuple)
                    else item
                )
                for key, item in command.items()
            },
        }
        for command in backend_events
    )
    if inspection.diagnostics:
        entries.append(
            {
                "event": "tsk_diagnostics",
                "messages": tuple(
                    message.replace(str(summary.source), "<SOURCE>")
                    for message in inspection.diagnostics
                ),
            }
        )
    with destination.open("x", encoding="utf-8") as output:
        for item in entries:
            output.write(json.dumps(item, ensure_ascii=False) + "\n")
