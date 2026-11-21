"""PhotoRec carving normalization, hashing, deduplication, and reporting."""

import errno
import json
import os
import shutil
import tempfile
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.recovery.carving.photorec_backend import PhotoRecBackend
from forensic_image_scanner.recovery.carving.photorec_runner import PhotoRecError
from forensic_image_scanner.recovery.media_types import candidate_media_kind
from forensic_image_scanner.recovery.models import (
    CarvedMedia,
    MediaKind,
    RecoveryMethod,
    RecoverySessionSummary,
    RecoveryStatus,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.reports import write_recovery_reports
from forensic_image_scanner.recovery.service import MIN_FREE_BYTES


@dataclass(frozen=True, slots=True)
class CarvingRequest:
    source: Path
    target: Path
    volume_ids: tuple[str, ...] = ()
    images: bool = True
    videos: bool = True


class PhotoRecCarvingService:
    def __init__(self, backend: PhotoRecBackend | None = None) -> None:
        self.backend = backend or PhotoRecBackend()

    def carve(
        self,
        request: CarvingRequest,
        *,
        inspection: SourceInspection | None = None,
        base_summary: RecoverySessionSummary | None = None,
        cancel: threading.Event | None = None,
        progress: Callable[[str, int, int, str], None] | None = None,
    ) -> RecoverySessionSummary:
        source = request.source.expanduser().resolve()
        target = request.target.expanduser().resolve()
        if not source.is_file():
            raise ValueError("source must be a readable forensic image")
        if target in {source, source.parent}:
            raise ValueError("target must be separate from the source image")
        for existing in (
            target / "reports" / "recovery.json",
            target / "reports" / "recovery.csv",
            target / "logs" / "recovery.log",
        ):
            if existing.exists():
                raise FileExistsError(f"recovery session output already exists: {existing}")
        media = frozenset(
            kind
            for kind, selected in (
                (MediaKind.IMAGE, request.images),
                (MediaKind.VIDEO, request.videos),
            )
            if selected
        )
        if not media:
            raise ValueError("select images, videos, or both")
        cancel = cancel or threading.Event()
        before = source.stat()
        started = base_summary.started_at if base_summary else datetime.now(UTC)
        volumes = _selected_volumes(source, inspection, request.volume_ids)
        target.mkdir(parents=True, exist_ok=True)
        temporary_parent = target / ".fis-tmp"
        temporary_parent.mkdir(exist_ok=True)
        session = Path(tempfile.mkdtemp(prefix="photorec-", dir=temporary_parent))
        records = list(base_summary.records if base_summary else ())
        hashes = {
            record.recovered_sha256: (record.recovery_id, record.recovered_relative_path)
            for record in records
            if record.recovered_sha256 and record.recovered_relative_path
        }
        carved_candidates = 0
        errors: list[dict[str, str]] = []
        plans: list[dict[str, object]] = []
        try:
            for volume_index, volume in enumerate(volumes, 1):
                if cancel.is_set():
                    break
                if progress:
                    progress("RAW CARVING", volume_index, len(volumes), volume.volume_id)
                try:
                    if shutil.disk_usage(target).free < MIN_FREE_BYTES:
                        raise OSError(errno.ENOSPC, "target free space safety threshold reached")
                    output = self.backend.carve(source, inspection, volume, media, session, cancel)
                    plans.append(
                        {
                            "volume_id": volume.volume_id,
                            "scan_scope": output.plan.scan_scope,
                            "format_groups": output.plan.format_groups,
                            "partition_number": output.plan.partition_number,
                        }
                    )
                    _preserve_photorec_log(output.log_path, target, source, volume.volume_id)
                    candidates = _candidate_files(output.root, media)
                    carved_candidates += len(candidates)
                    for index, candidate in enumerate(candidates, 1):
                        if cancel.is_set() and not output.cancelled:
                            break
                        if progress:
                            progress("NORMALIZING", index, len(candidates), candidate.name)
                        record = _normalize(
                            candidate,
                            target,
                            volume.volume_id,
                            self.backend.capability.version or "unknown",
                            hashes,
                        )
                        records.append(record)
                    if output.cancelled:
                        cancel.set()
                        break
                except PhotoRecError as exc:
                    if exc.code == "CANCELLED":
                        cancel.set()
                        break
                    errors.append(
                        {"volume_id": volume.volume_id, "error_type": exc.code, "message": str(exc)}
                    )
                except OSError as exc:
                    code = "FAILED_TARGET_FULL" if exc.errno == errno.ENOSPC else "CARVING_FAILED"
                    errors.append(
                        {"volume_id": volume.volume_id, "error_type": code, "message": str(exc)}
                    )
                    if exc.errno == errno.ENOSPC:
                        break
        finally:
            for log_path in session.glob("photorec-*.log"):
                volume_id = log_path.stem.removeprefix("photorec-")
                destination = target / "logs" / log_path.name
                if not destination.exists():
                    _preserve_photorec_log(log_path, target, source, volume_id)
            if session.resolve().is_relative_to(temporary_parent.resolve()):
                shutil.rmtree(session, ignore_errors=True)
            with suppress(OSError):
                temporary_parent.rmdir()
        after = source.stat()
        metadata = dict(base_summary.metadata) if base_summary else {}
        metadata.update(
            {
                "carving_engine": "PhotoRec",
                "carving_engine_version": self.backend.capability.version,
                "carving_plans": tuple(plans),
                "carving_errors": tuple(errors),
                "source_stat_before": {
                    "size_bytes": before.st_size,
                    "mtime_ns": before.st_mtime_ns,
                },
                "source_stat_after": {"size_bytes": after.st_size, "mtime_ns": after.st_mtime_ns},
            }
        )
        summary = RecoverySessionSummary(
            source=source,
            target=target,
            tsk_version=base_summary.tsk_version if base_summary else "NOT USED",
            started_at=started,
            completed_at=datetime.now(UTC),
            volumes_inspected=(base_summary.volumes_inspected if base_summary else len(volumes)),
            filesystems_detected=(base_summary.filesystems_detected if base_summary else 0),
            deleted_entries=base_summary.deleted_entries if base_summary else 0,
            media_candidates=(base_summary.media_candidates if base_summary else 0)
            + carved_candidates,
            records=tuple(records),
            cancelled=cancel.is_set(),
            source_sha256=base_summary.source_sha256 if base_summary else None,
            source_stat_unchanged=(before.st_size, before.st_mtime_ns)
            == (after.st_size, after.st_mtime_ns),
            method=(base_summary.method if base_summary else RecoveryMethod.FILE_CARVING),
            metadata=metadata,
        )
        if progress:
            progress("DEDUPLICATING", len(records), len(records), "SHA-256 provenance")
            progress("WRITING REPORT", 1, 1, "recovery.json")
        json_path, csv_path = write_recovery_reports(summary)
        _write_log(summary)
        return replace(summary, json_path=json_path, csv_path=csv_path)


def _selected_volumes(
    source: Path, inspection: SourceInspection | None, selected_ids: tuple[str, ...]
) -> tuple[RecoveryVolume, ...]:
    if inspection is None:
        return (
            RecoveryVolume(
                "volume-01", 0, None, "Whole forensic image", None, False, 512, source.name
            ),
        )
    volumes = inspection.supported_volumes or inspection.volumes
    selected = set(selected_ids)
    missing = selected - {volume.volume_id for volume in volumes}
    if missing:
        raise ValueError(f"unknown volume: {', '.join(sorted(missing))}")
    return tuple(volume for volume in volumes if not selected or volume.volume_id in selected)


def _candidate_files(root: Path, media: frozenset[MediaKind]) -> tuple[Path, ...]:
    if not root.exists():
        return ()
    return tuple(
        path
        for path in sorted(root.rglob("*"))
        if path.is_file()
        and not path.is_symlink()
        and (kind := candidate_media_kind(path.name)) is not None
        and kind in media
    )


def _normalize(
    candidate: Path,
    target: Path,
    volume_id: str,
    version: str,
    hashes: dict[str, tuple[str, str]],
) -> CarvedMedia:
    kind = candidate_media_kind(candidate.name)
    if kind is None:
        raise ValueError("candidate extension is outside the media policy")
    size = candidate.stat().st_size
    extension = candidate.suffix.casefold()
    recovery_id = f"carve_{volume_id}_{candidate.stem}"
    if size == 0:
        return CarvedMedia(
            recovery_id,
            volume_id,
            kind,
            extension,
            0,
            None,
            None,
            "PhotoRec",
            version,
            RecoveryStatus.FAILED,
            error_type="EMPTY_OUTPUT",
            error_message="zero-byte output",
        )
    if shutil.disk_usage(target).free < MIN_FREE_BYTES:
        raise OSError(errno.ENOSPC, "target free space safety threshold reached")
    digest = sha256_file(candidate)
    if digest in hashes:
        duplicate_id, canonical = hashes[digest]
        candidate.unlink(missing_ok=True)
        return CarvedMedia(
            recovery_id,
            volume_id,
            kind,
            extension,
            size,
            digest,
            canonical,
            "PhotoRec",
            version,
            RecoveryStatus.SKIPPED,
            duplicate_of=duplicate_id,
            error_type="DUPLICATE",
            error_message="identical SHA-256 already recovered",
        )
    category = "images" if kind is MediaKind.IMAGE else "videos"
    destination = (
        target
        / "recovered"
        / "carved"
        / volume_id
        / category
        / f"carve_{volume_id}_{digest[:20]}{extension}"
    ).resolve()
    if not destination.is_relative_to(target.resolve()):
        raise ValueError("carving destination escaped target")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"carved destination already exists: {destination}")
    os.replace(candidate, destination)
    relative = str(destination.relative_to(target))
    hashes[digest] = (recovery_id, relative)
    return CarvedMedia(
        recovery_id, volume_id, kind, extension, size, digest, relative, "PhotoRec", version
    )


def _write_log(summary: RecoverySessionSummary) -> None:
    logs = summary.target / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    destination = logs / "recovery.log"
    if destination.exists():
        raise FileExistsError("a recovery log already exists in this target")
    with destination.open("x", encoding="utf-8") as output:
        output.write(
            json.dumps(
                {
                    "event": "carving_session",
                    "source_identifier": summary.source.name,
                    "engine": "PhotoRec",
                    "version": summary.metadata.get("carving_engine_version"),
                    "plans": summary.metadata.get("carving_plans"),
                    "errors": summary.metadata.get("carving_errors"),
                },
                ensure_ascii=False,
            )
            + "\n"
        )


def _preserve_photorec_log(source_log: Path, target: Path, source: Path, volume_id: str) -> None:
    logs = target / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    destination = logs / f"photorec-{volume_id}.log"
    if destination.exists():
        raise FileExistsError(f"PhotoRec log already exists: {destination}")
    with (
        source_log.open("r", encoding="utf-8", errors="replace") as incoming,
        destination.open("x", encoding="utf-8") as outgoing,
    ):
        for line in incoming:
            outgoing.write(line.replace(str(source), "<SOURCE>"))
