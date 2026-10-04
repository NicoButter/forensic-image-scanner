"""Verified, explicit export and working-copy move transactions."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from forensic_image_scanner.audit_service import AuditService
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.results import (
    ExportStatus,
    ImageAnalysisResult,
    MoveStatus,
    SourceMode,
)

ProgressCallback = Callable[[int, int, ImageAnalysisResult], None]
FileStartedCallback = Callable[[int, int, ImageAnalysisResult], None]


class ExportService:
    """Copy selected analyzed files without weakening evidence protections."""

    def __init__(self, source_root: str | Path, output: str | Path) -> None:
        self.source_root = Path(source_root).expanduser().resolve()
        self.output = Path(output).expanduser().resolve()
        self.exported_root = self.output / "exported"
        self.audit = AuditService(self.output)

    def export_result(self, result: ImageAnalysisResult) -> ImageAnalysisResult:
        """Create one verified copy, preserving triage and relative hierarchy."""
        return self._transfer_one(result, move=False)

    def export_results(
        self,
        results: Iterable[ImageAnalysisResult],
        *,
        cancelled: Callable[[], bool] | None = None,
        file_started: FileStartedCallback | None = None,
        progress: ProgressCallback | None = None,
    ) -> list[ImageAnalysisResult]:
        return self._transfer_many(
            results,
            move=False,
            cancelled=cancelled,
            file_started=file_started,
            progress=progress,
        )

    def move_result(
        self, result: ImageAnalysisResult, *, source_mode: SourceMode
    ) -> ImageAnalysisResult:
        """Copy, verify, finalize, then remove one explicit working-copy file."""
        self._require_working_copy(source_mode)
        return self._transfer_one(result, move=True)

    def move_results(
        self,
        results: Iterable[ImageAnalysisResult],
        *,
        source_mode: SourceMode,
        cancelled: Callable[[], bool] | None = None,
        file_started: FileStartedCallback | None = None,
        progress: ProgressCallback | None = None,
    ) -> list[ImageAnalysisResult]:
        self._require_working_copy(source_mode)
        return self._transfer_many(
            results,
            move=True,
            cancelled=cancelled,
            file_started=file_started,
            progress=progress,
        )

    def _transfer_many(
        self,
        results: Iterable[ImageAnalysisResult],
        *,
        move: bool,
        cancelled: Callable[[], bool] | None,
        file_started: FileStartedCallback | None,
        progress: ProgressCallback | None,
    ) -> list[ImageAnalysisResult]:
        requested = list(results)
        completed: list[ImageAnalysisResult] = []
        for index, result in enumerate(requested, start=1):
            if cancelled is not None and cancelled():
                break
            if file_started is not None:
                file_started(index, len(requested), result)
            updated = self._transfer_one(result, move=move)
            completed.append(updated)
            if progress is not None:
                progress(index, len(requested), updated)
        return completed

    @staticmethod
    def _require_working_copy(source_mode: SourceMode) -> None:
        if source_mode is not SourceMode.WORKING_COPY:
            raise PermissionError(
                "Moving files is disabled for evidence sources. "
                "Use Export to preserve the original evidence."
            )

    def _transfer_one(self, result: ImageAnalysisResult, *, move: bool) -> ImageAnalysisResult:
        action = "move" if move else "export"
        in_progress = replace(
            result,
            export_status=ExportStatus.EXPORTING if not move else result.export_status,
            move_status=MoveStatus.MOVING if move else result.move_status,
            source_verified_before_export=False,
            source_removed=False if move else result.source_removed,
        )
        self.audit.record(f"{action} requested", result.relative_path)
        try:
            source, destination = self._validated_paths(result)
            expected = result.sha256.casefold()
            if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
                raise ValueError("result has no valid original SHA-256")
            source_hash = sha256_file(source)
            if source_hash != expected:
                raise ValueError("SOURCE MODIFIED SINCE ANALYSIS")
            self.audit.record(f"{action} source integrity verified", result.relative_path)
            copied = self._verified_copy(
                source, destination, expected, result.relative_path, action
            )
            updated = replace(
                in_progress,
                export_status=ExportStatus.EXPORTED,
                exported_path=copied,
                export_timestamp=datetime.now(UTC),
                exported_sha256=expected,
                source_verified_before_export=True,
            )
            if not move:
                self.audit.record("export completed", result.relative_path, str(copied))
                return updated
            try:
                source.unlink()
            except OSError as exc:
                self.audit.record("move source deletion failed", result.relative_path, str(exc))
                return replace(
                    updated,
                    move_status=MoveStatus.MOVE_PARTIAL,
                    source_removed=False,
                    error_type=type(exc).__name__,
                    error_message=(
                        "MOVE_PARTIAL: destination verified but source was not deleted: "
                        f"{exc}"
                    ),
                )
            self.audit.record("move source deleted", result.relative_path)
            self.audit.record("move completed", result.relative_path, str(copied))
            return replace(updated, move_status=MoveStatus.MOVED, source_removed=True)
        except Exception as exc:
            self.audit.record(f"{action} failed", result.relative_path, str(exc))
            if move:
                return replace(
                    in_progress,
                    move_status=MoveStatus.MOVE_FAILED,
                    source_removed=False,
                    error_type=type(exc).__name__,
                    error_message=str(exc),
                )
            return replace(
                in_progress,
                export_status=ExportStatus.EXPORT_FAILED,
                error_type=type(exc).__name__,
                error_message=str(exc),
            )

    def _validated_paths(self, result: ImageAnalysisResult) -> tuple[Path, Path]:
        if result.status == "error" or result.triage is None:
            raise ValueError("error results cannot be exported")
        if not self.source_root.is_dir():
            raise ValueError(f"source root is not a directory: {self.source_root}")
        relative = Path(result.relative_path)
        if relative.is_absolute() or ".." in relative.parts or relative == Path("."):
            raise ValueError("unsafe relative path in result")
        # Reconstruct from the root rather than trusting a report path supplied
        # by a caller, then reject source symlinks and all root escapes.
        source_candidate = self.source_root / relative
        if source_candidate.is_symlink():
            raise ValueError("symlinked source files cannot be exported")
        source = source_candidate.resolve(strict=True)
        if not source.is_relative_to(self.source_root) or not source.is_file():
            raise ValueError("source path escapes the selected source root")
        supplied = result.path.expanduser().resolve(strict=True)
        if supplied != source or result.path.is_symlink():
            raise ValueError("result source path does not match safe relative path")
        triage = result.triage.value
        if self.exported_root.is_symlink():
            raise ValueError("exported directory cannot be a symlink")
        self.exported_root.mkdir(parents=True, exist_ok=True)
        exported_root = self.exported_root.resolve()
        destination = self.exported_root / triage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = destination.parent.resolve()
        resolved_destination = destination.resolve()
        if (
            not resolved_parent.is_relative_to(exported_root)
            or not resolved_destination.is_relative_to(exported_root)
        ):
            raise ValueError("destination path escapes exported directory")
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(f"destination already exists: {destination}")
        return source, destination

    def _verified_copy(
        self,
        source: Path,
        destination: Path,
        expected: str,
        relative_path: str,
        action: str,
    ) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            shutil.copy2(source, temporary)
            self.audit.record(f"{action} copy completed", relative_path)
            destination_hash = sha256_file(temporary)
            if destination_hash != expected:
                raise ValueError("destination SHA-256 does not match original SHA-256")
            self.audit.record(f"{action} destination integrity verified", relative_path)
            os.replace(temporary, destination)
            return destination
        finally:
            temporary.unlink(missing_ok=True)
