"""Read-only discovery of a locally labelled calibration corpus."""

from pathlib import Path
from typing import Literal

from forensic_image_scanner.analysis_service import discover_image_files

ClassLabel = Literal["normal", "nsfw"]


def discover_corpus(root: Path) -> list[tuple[Path, ClassLabel]]:
    """Find images recursively under the required normal/ and nsfw/ directories."""
    if not root.is_dir():
        raise ValueError(f"calibration corpus is not a directory: {root}")

    files: list[tuple[Path, ClassLabel]] = []
    labels: tuple[ClassLabel, ...] = ("normal", "nsfw")
    for label in labels:
        directory = root / label
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"calibration corpus requires a local {label}/ directory")
        files.extend((path, label) for path in discover_image_files(directory))

    if not files:
        raise ValueError("calibration corpus has no supported images")
    return files
