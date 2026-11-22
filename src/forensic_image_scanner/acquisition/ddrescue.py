"""Conservative GNU ddrescue acquisition with a persistent mapfile."""

import re
import threading
from pathlib import Path

from forensic_image_scanner.acquisition.runner import run_owned, tool_help


def acquire_raw(
    source: Path,
    directory: Path,
    binary: Path,
    cancel: threading.Event,
    *,
    resume: bool = False,
    expected_size: int | None = None,
) -> tuple[Path, Path, tuple[str, ...]]:
    image, mapfile = directory / "source.raw", directory / "source.map"
    if resume:
        if (
            not image.is_file()
            or image.is_symlink()
            or not mapfile.is_file()
            or mapfile.is_symlink()
            or image.stat().st_nlink != 1
            or mapfile.stat().st_nlink != 1
        ):
            raise ValueError("RESUME_REQUIRES_EXISTING_RAW_AND_MAPFILE")
    elif image.is_symlink() or mapfile.is_symlink() or image.exists() or mapfile.exists():
        raise FileExistsError("RAW output or mapfile already exists")
    help_text = tool_help(binary)
    short = re.search(r"(?<![\w-])-n(?:\s|,|$)", help_text)
    long = re.search(r"(?<![\w-])--no-scrape(?:\s|,|$)", help_text)
    if not short and not long:
        raise RuntimeError("DDRESCUE_CONSERVATIVE_OPTION_UNAVAILABLE")
    status = run_owned(
        [str(binary), "-n" if short else "--no-scrape", str(source), str(image), str(mapfile)],
        directory / "acquisition.log",
        cancel,
    )
    errors = [] if status == 0 else ["DDRESCUE_FAILED"]
    if not mapfile.is_file() or mapfile.is_symlink():
        errors.append("DDRESCUE_MAPFILE_MISSING")
    elif expected_size is not None:
        try:
            errors.extend(_map_errors(mapfile, expected_size))
        except (OSError, ValueError):
            errors.append("DDRESCUE_MAPFILE_UNREADABLE")
    if not image.is_file() or image.is_symlink():
        errors.append("DDRESCUE_OUTPUT_MISSING")
    elif expected_size is not None and image.stat().st_size != expected_size:
        errors.append("DDRESCUE_OUTPUT_SIZE_MISMATCH")
    return image, mapfile, tuple(errors)


def _map_stats(mapfile: Path, expected_size: int) -> tuple[int, int, int]:
    """Validate complete map coverage and count unfinished and bad-sector bytes."""
    offset = unfinished = bad = last_finished_end = 0
    with mapfile.open(encoding="ascii") as file:
        for line in file:
            columns = line.split()
            if len(columns) != 3 or columns[2] not in {"?", "*", "/", "-", "+"}:
                continue
            start, size = int(columns[0], 0), int(columns[1], 0)
            if start != offset or size <= 0:
                raise ValueError("invalid map ranges")
            offset += size
            if columns[2] != "+":
                unfinished += size
            if columns[2] == "-":
                bad += size
            if columns[2] == "+":
                last_finished_end = offset
    if offset != expected_size:
        raise ValueError("map does not cover the source")
    return unfinished, bad, last_finished_end


def _map_errors(mapfile: Path, expected_size: int) -> list[str]:
    """Report unfinished and bad-sector ranges after validating the map."""
    unfinished, bad, _last_finished_end = _map_stats(mapfile, expected_size)
    errors = []
    if unfinished:
        errors.append(f"DDRESCUE_UNRECOVERED_BYTES: {unfinished}")
    if bad:
        errors.append(f"DDRESCUE_BAD_SECTOR_BYTES: {bad}")
    return errors
