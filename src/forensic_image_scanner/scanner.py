"""Compatibility boundary delegating directory scans to AnalysisService."""

from __future__ import annotations

from forensic_image_scanner.analysis_service import AnalysisRequest, AnalysisService
from forensic_image_scanner.results import AnalysisSummary


def scan_directory(
    request: AnalysisRequest,
    service: AnalysisService,
) -> AnalysisSummary:
    """Run the shared sequential service without duplicating scan logic."""
    return service.run(request)
