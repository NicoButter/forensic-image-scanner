"""Scanner orchestration boundary.

Directory discovery and detector execution intentionally remain unimplemented in
the bootstrap milestone. This module establishes the API without coupling it to
specific detection engines.
"""

from collections.abc import Sequence
from pathlib import Path

from forensic_image_scanner.detectors.base import Detector
from forensic_image_scanner.results import AnalysisResult


class ScannerNotImplementedError(NotImplementedError):
    """Raised while the mass-scanning pipeline is still a documented scaffold."""


def scan_directory(path: Path, detectors: Sequence[Detector]) -> list[AnalysisResult]:
    """Scan a directory without mutating evidence (future milestone)."""
    if not path.is_dir():
        raise NotADirectoryError(path)
    del detectors
    raise ScannerNotImplementedError(
        "Mass scanning is not implemented in this bootstrap release; no files were processed."
    )
