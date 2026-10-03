"""HTML report boundary reserved for a future milestone."""

from collections.abc import Iterable
from pathlib import Path

from forensic_image_scanner.results import AnalysisResult


def write_html_report(results: Iterable[AnalysisResult], destination: Path) -> None:
    """Document that HTML generation is intentionally not implemented yet."""
    del results, destination
    raise NotImplementedError("HTML reports are outside the bootstrap milestone")
