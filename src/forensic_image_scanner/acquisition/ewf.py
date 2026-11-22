"""System libewf acquisition and verification processes."""

import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from forensic_image_scanner.acquisition.runner import run_owned, tool_help


@dataclass(frozen=True, slots=True)
class EwfOutcome:
    image: Path
    verification_succeeded: bool
    errors: tuple[str, ...] = ()


def _supports(help_text: str, option: str) -> bool:
    return re.search(rf"(?<![\w-]){re.escape(option)}(?:\s|,|:|=|$)", help_text) is not None


def acquire_ewf(
    source: Path,
    directory: Path,
    acquire_binary: Path,
    verify_binary: Path,
    cancel: threading.Event,
    metadata: dict[str, str] | None = None,
    progress: Callable[[str, int, int, str], None] | None = None,
) -> EwfOutcome:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("unsafe EWF output directory")
    if any(directory.glob("source.*")):
        raise FileExistsError("EWF output already exists")
    help_text = tool_help(acquire_binary)
    if not _supports(help_text, "-u") or not _supports(help_text, "-t"):
        raise RuntimeError("EWF_UNATTENDED_OPTIONS_UNAVAILABLE")
    prefix = directory / "source"
    command = [str(acquire_binary), "-u", "-t", str(prefix)]
    if _supports(help_text, "-d") and "sha256" in help_text.casefold():
        command += ["-d", "sha256"]
    for key, option in (
        ("case_number", "-C"),
        ("evidence_number", "-E"),
        ("examiner", "-e"),
        ("description", "-D"),
        ("notes", "-N"),
    ):
        value = (metadata or {}).get(key)
        if value:
            if not _supports(help_text, option):
                raise RuntimeError(f"EWF_METADATA_OPTION_UNAVAILABLE: {key}")
            command += [option, value]
    command.append(str(source))
    image = directory / "source.E01"
    if run_owned(command, directory / "acquisition.log", cancel):
        return EwfOutcome(image, False, ("EWF_ACQUISITION_FAILED",))
    if not image.is_file() or image.is_symlink():
        return EwfOutcome(image, False, ("EWF_OUTPUT_MISSING",))
    if cancel.is_set():
        from forensic_image_scanner.acquisition.runner import AcquisitionCancelled

        raise AcquisitionCancelled("acquisition cancelled before verification")
    verification_command = [str(verify_binary), str(image)]
    if progress is None:
        status = run_owned(verification_command, directory / "verification.log", cancel)
    else:
        status = run_owned(
            verification_command,
            directory / "verification.log",
            cancel,
            on_started=lambda: progress("VERIFYING", 0, 1, str(image)),
        )
    return EwfOutcome(image, status == 0, () if status == 0 else ("EWF_VERIFICATION_FAILED",))
