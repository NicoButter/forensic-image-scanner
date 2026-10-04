"""JSON report serialization."""

import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from forensic_image_scanner.results import ImageAnalysisResult


def write_json_report(results: Iterable[ImageAnalysisResult], destination: Path) -> None:
    """Atomically write complete UTF-8 JSON without touching evidence files."""
    payload = [result.to_dict() for result in results]
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(payload, output, indent=2, ensure_ascii=False)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
