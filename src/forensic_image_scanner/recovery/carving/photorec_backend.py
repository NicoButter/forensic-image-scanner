"""PhotoRec argument-array backend."""

import os
import threading
from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.recovery.carving.photorec_config import PhotoRecPlan, build_plan
from forensic_image_scanner.recovery.carving.photorec_runner import PhotoRecError, PhotoRecRunner
from forensic_image_scanner.recovery.carving.probe import PhotoRecCapability, probe_photorec
from forensic_image_scanner.recovery.models import MediaKind, RecoveryVolume, SourceInspection


@dataclass(frozen=True, slots=True)
class PhotoRecOutput:
    root: Path
    plan: PhotoRecPlan
    log_path: Path
    cancelled: bool = False


class PhotoRecBackend:
    def __init__(
        self,
        capability: PhotoRecCapability | None = None,
        runner: PhotoRecRunner | None = None,
    ) -> None:
        self.capability = capability or probe_photorec()
        self.runner = runner or PhotoRecRunner()

    def carve(
        self,
        source: Path,
        inspection: SourceInspection | None,
        volume: RecoveryVolume,
        media: frozenset[MediaKind],
        session_directory: Path,
        cancel: threading.Event,
    ) -> PhotoRecOutput:
        if not self.capability.available or self.capability.binary is None:
            raise PhotoRecError("PHOTOREC_NOT_AVAILABLE", "system PhotoRec is not available")
        if not source.is_file() or not os.access(source, os.R_OK):
            raise PhotoRecError("IMAGE_UNREADABLE", "source image is not a readable file")
        plan = build_plan(inspection, volume, media)
        output_base = session_directory / f"raw-{volume.volume_id}"
        log_path = session_directory / f"photorec-{volume.volume_id}.log"
        arguments = [
            str(self.capability.binary),
            "/d",
            str(output_base),
            "/cmd",
            str(source),
            plan.command,
        ]
        cancelled = False
        try:
            returncode = self.runner.run(
                arguments,
                cwd=session_directory,
                log_path=log_path,
                timeout=24 * 60 * 60,
                cancel=cancel,
            )
        except PhotoRecError as exc:
            if exc.code != "CANCELLED":
                raise
            returncode = 0
            cancelled = True
        if returncode != 0:
            raise PhotoRecError("CARVING_FAILED", f"PhotoRec exited with code {returncode}")
        diagnostic = log_path.read_text(encoding="utf-8", errors="replace")
        if "PhotoRec syntax error:" in diagnostic:
            detail = diagnostic.rsplit("PhotoRec syntax error:", 1)[-1].strip()
            raise PhotoRecError("FORMAT_CONFIGURATION_UNSUPPORTED", detail)
        roots = sorted(session_directory.glob(f"{output_base.name}.*"))
        root = roots[0] if roots else output_base
        return PhotoRecOutput(root, plan, log_path, cancelled)
