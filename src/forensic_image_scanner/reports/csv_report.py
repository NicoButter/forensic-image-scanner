"""CSV report serialization."""

import csv
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from forensic_image_scanner.results import ImageAnalysisResult

FIELDS = (
    "triage",
    "nsfw_score",
    "normal_score",
    "sha256",
    "size_bytes",
    "mime_type",
    "filename",
    "relative_path",
    "status",
    "error",
)


def write_csv_report(results: Iterable[ImageAnalysisResult], destination: Path) -> None:
    """Atomically write a compact, spreadsheet-safe inspection report."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            writer = csv.DictWriter(output, fieldnames=FIELDS)
            writer.writeheader()
            for result in results:
                data = result.to_dict()
                writer.writerow(
                    {
                        field: _safe_cell(data.get(field, ""))
                        for field in FIELDS
                    }
                )
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_cell(value: object) -> object:
    """Prevent spreadsheet formula execution while preserving visible text."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return f"'{value}"
    return value
