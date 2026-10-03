"""CSV report serialization."""

import csv
from collections.abc import Iterable
from pathlib import Path

from forensic_image_scanner.results import AnalysisResult

FIELDS = (
    "file",
    "sha256",
    "mime_type",
    "size_bytes",
    "detector_name",
    "detector_version",
    "model_name",
    "model_version",
    "model_sha256",
    "confidence",
    "classification",
    "analyzed_at",
    "detections",
    "errors",
)


def write_csv_report(results: Iterable[AnalysisResult], destination: Path) -> None:
    """Write a tabular audit report."""
    with destination.open("w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=FIELDS)
        writer.writeheader()
        for result in results:
            row = result.to_dict()
            row["detections"] = repr(row["detections"])
            row["errors"] = repr(row["errors"])
            writer.writerow(row)
