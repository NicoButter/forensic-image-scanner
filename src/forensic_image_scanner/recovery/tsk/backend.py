"""Filesystem inspection and extraction through system TSK tools."""

import os
import threading
import time
from pathlib import Path

from forensic_image_scanner.recovery.models import (
    DeletedMediaEntry,
    RecoveryVolume,
    SourceInspection,
)
from forensic_image_scanner.recovery.tsk.parsers import parse_fls, parse_fsstat, parse_mmls
from forensic_image_scanner.recovery.tsk.probe import TskCapability, probe_tsk
from forensic_image_scanner.recovery.tsk.runner import TskCommandError, TskRunner


class TskBackend:
    def __init__(
        self, capability: TskCapability | None = None, runner: TskRunner | None = None
    ) -> None:
        self.capability = capability or probe_tsk()
        self.runner = runner or TskRunner()
        self.events: list[dict[str, object]] = []

    def inspect(self, source: Path) -> SourceInspection:
        self._require_ready(source)
        diagnostics: list[str] = []
        mmls = self._text("mmls", [str(source)], timeout=30)
        diagnostics.append(mmls.stderr.strip())
        volume_system, sector_size, rows = parse_mmls(mmls.stdout)
        volumes: list[RecoveryVolume] = []
        for index, row in enumerate(rows, 1):
            volumes.append(
                self._inspect_volume(
                    source,
                    f"volume-{index:02d}",
                    int(row["start_sector"]),
                    int(row["length_sectors"]),
                    str(row["description"]),
                    sector_size,
                    str(row["partition_slot"] or row["slot"]),
                    diagnostics,
                )
            )
        if not volumes:
            volume_system = "SINGLE_FILESYSTEM_IMAGE"
            volumes.append(
                self._inspect_volume(
                    source, "volume-01", 0, None, "Filesystem image", sector_size, None, diagnostics
                )
            )
        inspection = SourceInspection(
            source,
            volume_system,
            sector_size,
            tuple(volumes),
            self.capability.version or "unknown",
            tuple(item for item in diagnostics if item),
        )
        if not inspection.supported_volumes and source.suffix.casefold() in {".e01", ".ex01"}:
            raise TskCommandError(
                "EWF_SUPPORT_UNAVAILABLE",
                "EWF support unavailable in installed The Sleuth Kit build.",
            )
        return inspection

    def enumerate_deleted(
        self, source: Path, volume: RecoveryVolume
    ) -> tuple[tuple[DeletedMediaEntry, ...], int]:
        arguments = ["-r", "-d", "-p", "-l"]
        if volume.start_sector:
            arguments += ["-o", str(volume.start_sector)]
        arguments.append(str(source))
        result = self._text("fls", arguments, timeout=300)
        if result.returncode != 0:
            raise TskCommandError("ENUMERATION_FAILED", result.stderr.strip() or "fls failed")
        deleted_count = sum(
            line.lstrip("+").lstrip().startswith(("r/", "-/", "d/", "l/", "v/"))
            and "*" in line.split("\t", 1)[0]
            for line in result.stdout.splitlines()
        )
        return (
            parse_fls(result.stdout, volume.volume_id, volume.filesystem or "unknown"),
            deleted_count,
        )

    def extract(
        self,
        source: Path,
        volume: RecoveryVolume,
        entry: DeletedMediaEntry,
        destination: Path,
        cancel: threading.Event,
    ) -> None:
        tool = self._tool("icat")
        arguments = [str(tool), "-r"]
        if volume.start_sector:
            arguments += ["-o", str(volume.start_sector)]
        arguments += [str(source), entry.metadata_address]
        started = time.monotonic()
        result = self.runner.extract(arguments, destination, timeout=600, cancel=cancel)
        self.events.append(
            {
                "tool": "icat",
                "arguments": tuple(arguments),
                "returncode": result.returncode,
                "elapsed_seconds": time.monotonic() - started,
            }
        )
        if result.returncode != 0:
            raise TskCommandError("RECOVERY_FAILED", result.stderr.strip() or "icat failed")

    def _inspect_volume(
        self,
        source: Path,
        volume_id: str,
        start: int,
        length: int | None,
        description: str,
        sector_size: int,
        slot: str | None,
        diagnostics: list[str],
    ) -> RecoveryVolume:
        arguments = []
        if start:
            arguments += ["-o", str(start)]
        arguments.append(str(source))
        result = self._text("fsstat", arguments, timeout=60)
        diagnostics.append(result.stderr.strip())
        filesystem, label = parse_fsstat(result.stdout) if result.returncode == 0 else (None, None)
        return RecoveryVolume(
            volume_id,
            start,
            length,
            description,
            filesystem,
            filesystem is not None,
            sector_size,
            source.name,
            label,
            slot,
        )

    def _require_ready(self, source: Path) -> None:
        if not self.capability.available:
            raise TskCommandError("TSK_NOT_AVAILABLE", "required tools: mmls, fsstat, fls, icat")
        if not source.is_file() or not source.exists() or not os.access(source, os.R_OK):
            raise TskCommandError("IMAGE_UNREADABLE", "source image is not a readable file")

    def _text(self, tool_name: str, arguments: list[str], *, timeout: float):
        tool = self._tool(tool_name)
        command = [str(tool), *arguments]
        started = time.monotonic()
        result = self.runner.run_text(command, timeout=timeout)
        self.events.append(
            {
                "tool": tool_name,
                "arguments": tuple(command),
                "returncode": result.returncode,
                "elapsed_seconds": time.monotonic() - started,
            }
        )
        return result

    def _tool(self, name: str) -> Path:
        tool = self.capability.tools.get(name)
        if tool is None:
            raise TskCommandError("TSK_NOT_AVAILABLE", f"missing required tool: {name}")
        return tool
