"""Safety-gated acquisition orchestration and durable case record."""

import json
import logging
import os
import tempfile
import threading
from collections.abc import Callable
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.acquisition.ddrescue import _map_errors, _map_stats, acquire_raw
from forensic_image_scanner.acquisition.ewf import acquire_ewf
from forensic_image_scanner.acquisition.models import (
    AcquisitionMethod,
    AcquisitionRequest,
    AcquisitionResult,
    VerificationStatus,
)
from forensic_image_scanner.acquisition.probe import probe_acquisition_tools
from forensic_image_scanner.acquisition.runner import AcquisitionCancelled, tool_version
from forensic_image_scanner.acquisition.safety import check_acquisition_safety

LOGGER = logging.getLogger(__name__)


class AcquisitionService:
    def acquire(
        self,
        request: AcquisitionRequest,
        *,
        cancel: threading.Event | None = None,
        progress: Callable[[str, int, int, str], None] | None = None,
    ):
        cancel = cancel or threading.Event()
        method = AcquisitionMethod(request.method)
        if request.resume and method is not AcquisitionMethod.RAW:
            raise ValueError("resume is available only for RAW acquisition")
        source = request.source.expanduser().resolve()
        target = request.target.expanduser().resolve()
        if progress is not None:
            progress("CHECKING SAFETY", 0, 1, str(source))
        safety = check_acquisition_safety(source, target, 0 if request.resume else None)
        if not safety.allowed or not safety.source_identity:
            raise ValueError("acquisition safety blocked: " + ", ".join(safety.errors))
        tools = probe_acquisition_tools()
        if method is AcquisitionMethod.E01:
            if not tools.e01_available:
                raise RuntimeError("EWF_TOOLS_NOT_AVAILABLE")
            binary, verifier = tools.ewfacquire, tools.ewfverify
        else:
            if not tools.raw_available:
                raise RuntimeError("DDRESCUE_NOT_AVAILABLE")
            binary, verifier = tools.ddrescue, None
        assert binary is not None
        directory = target / "acquisition"
        report = directory / "acquisition.json"
        resume_space = None
        if request.resume:
            if directory.is_symlink() or not directory.is_dir() or report.is_symlink():
                raise ValueError("RESUME_ACQUISITION_RECORD_REQUIRED")
            with report.open(encoding="utf-8") as existing:
                previous = json.load(existing)
            if (
                previous.get("method") != "raw"
                or previous.get("source") != str(source)
                or previous.get("source_identity") != safety.source_identity
                or previous.get("capacity_bytes") != safety.capacity_bytes
                or previous.get("serial") != safety.serial
            ):
                raise ValueError("RESUME_SOURCE_IDENTITY_MISMATCH")
            for filename in ("source.raw", "source.map"):
                path = directory / filename
                if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                    raise ValueError("RESUME_REQUIRES_EXISTING_RAW_AND_MAPFILE")
            if not safety.capacity_bytes:
                raise ValueError("RESUME_SOURCE_SIZE_UNKNOWN")
            try:
                unfinished, _bad, last_finished_end = _map_stats(
                    directory / "source.map", safety.capacity_bytes
                )
            except (OSError, ValueError) as exc:
                raise ValueError("RESUME_MAPFILE_INVALID") from exc
            raw_size = (directory / "source.raw").stat().st_size
            if raw_size < last_finished_end or raw_size > safety.capacity_bytes:
                raise ValueError("RESUME_RAW_FILE_INCONSISTENT_WITH_MAP")
            resume_space = max(unfinished, min(safety.capacity_bytes, 64 * 1024 * 1024))
        else:
            target.mkdir(parents=True, exist_ok=True)
            directory.mkdir(exist_ok=False)
        again = check_acquisition_safety(source, target, resume_space)
        if (
            not again.allowed
            or again.source_identity != safety.source_identity
            or again.target_disks != safety.target_disks
            or again.serial != safety.serial
            or again.capacity_bytes != safety.capacity_bytes
        ):
            raise ValueError("acquisition safety changed before execution")
        started = datetime.now(UTC)
        output = directory / ("source.E01" if method is AcquisitionMethod.E01 else "source.raw")
        mapfile = directory / "source.map" if method is AcquisitionMethod.RAW else None
        version = tool_version(binary)
        base = dict(
            source=str(source),
            source_identity=safety.source_identity,
            model=safety.model,
            serial=safety.serial,
            capacity_bytes=safety.capacity_bytes,
            transport=safety.transport,
            method=method,
            tool=str(binary),
            tool_version=version,
            started_at=started,
            output=str(output),
            bytes_acquired=None,
            sha256=None,
            mapfile=str(mapfile) if mapfile else None,
            case_metadata=dict(request.case_metadata),
            safety_warnings=safety.warnings,
        )
        initial = AcquisitionResult(
            **base,
            completed_at=started,
            verification=VerificationStatus.NOT_PERFORMED,
            completed=False,
            errors=("ACQUISITION_IN_PROGRESS",),
            cancelled=False,
        )
        _write_record(report, initial)
        errors: tuple[str, ...] = ()
        verification = VerificationStatus.NOT_PERFORMED
        cancelled = False
        completed = False
        try:
            if cancel.is_set():
                raise AcquisitionCancelled("acquisition cancelled before starting")
            if progress is not None:
                progress("ACQUIRING", 0, 1, str(source))
            if method is AcquisitionMethod.E01:
                assert verifier is not None
                if progress is None:
                    outcome = acquire_ewf(
                        source, directory, binary, verifier, cancel, request.case_metadata
                    )
                else:
                    outcome = acquire_ewf(
                        source,
                        directory,
                        binary,
                        verifier,
                        cancel,
                        request.case_metadata,
                        progress=progress,
                    )
                errors = outcome.errors
                if outcome.verification_succeeded:
                    verification = VerificationStatus.VERIFIED
                    completed = True
                elif "EWF_VERIFICATION_FAILED" in errors:
                    verification = VerificationStatus.FAILED
            else:
                _, _, errors = acquire_raw(
                    source,
                    directory,
                    binary,
                    cancel,
                    resume=request.resume,
                    expected_size=safety.capacity_bytes,
                )
                completed = not errors
        except AcquisitionCancelled as exc:
            cancelled = True
            errors = (f"CANCELLED: {exc}",)
            LOGGER.info("acquisition stage=execute error=CANCELLED")
        except Exception as exc:
            errors = (f"ACQUISITION_FAILED: {type(exc).__name__}: {exc}",)
            LOGGER.error(
                "acquisition stage=execute error=ACQUISITION_FAILED exception=%s",
                type(exc).__name__,
            )
        if (
            mapfile is not None
            and safety.capacity_bytes
            and mapfile.is_file()
            and not mapfile.is_symlink()
            and mapfile.stat().st_nlink == 1
        ):
            try:
                unfinished, bad, _last_finished_end = _map_stats(mapfile, safety.capacity_bytes)
                base["bytes_acquired"] = safety.capacity_bytes - unfinished
                base["read_error_bytes"] = bad
                errors += tuple(
                    error
                    for error in _map_errors(mapfile, safety.capacity_bytes)
                    if error not in errors
                )
            except (OSError, ValueError):
                pass
        result = AcquisitionResult(
            **base,
            completed_at=datetime.now(UTC),
            verification=verification,
            completed=completed,
            errors=errors,
            cancelled=cancelled,
        )
        _write_record(report, result)
        return result


def _write_record(path: Path, result: AcquisitionResult) -> None:
    descriptor, name = tempfile.mkstemp(prefix=".acquisition-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(asdict(result), output, default=str, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
