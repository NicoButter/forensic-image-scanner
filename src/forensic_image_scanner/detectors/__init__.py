"""Pluggable local detection engines."""

from forensic_image_scanner.detectors.base import Detector, DetectorOutput

__all__ = ["Detector", "DetectorOutput"]
