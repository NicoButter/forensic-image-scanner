"""JSON report serialization."""

import json
from collections.abc import Iterable
from pathlib import Path

from forensic_image_scanner.results import AnalysisResult


def write_json_report(results: Iterable[AnalysisResult], destination: Path) -> None:
    """Write deterministic, UTF-8 JSON without touching evidence files."""
    payload = [result.to_dict() for result in results]
    destination.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
