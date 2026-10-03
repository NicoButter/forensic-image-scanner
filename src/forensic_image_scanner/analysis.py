"""Single-image, read-only analysis orchestration."""

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from forensic_image_scanner.detectors.base import Detector, DetectorOutput
from forensic_image_scanner.detectors.exceptions import ImageDecodeError, UnsupportedImageError
from forensic_image_scanner.formats.standard import is_standard_image
from forensic_image_scanner.hashing import sha256_file
from forensic_image_scanner.image_loader import ImageLoadError, load_standard_image


@dataclass(frozen=True, slots=True)
class ImageAnalysis:
    """Auditable local result for one original image."""

    file: Path
    sha256: str
    size_bytes: int
    mime_type: str | None
    detector: DetectorOutput

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible audit record."""
        data = asdict(self)
        data["file"] = str(self.file)
        return data


def analyze_image_file(path: Path, detector: Detector) -> ImageAnalysis:
    """Hash original bytes, decode independently in memory, and analyze one image."""
    if not path.is_file():
        raise FileNotFoundError(path)
    if not is_standard_image(path):
        suffix = path.suffix or "(no extension)"
        raise UnsupportedImageError(f"unsupported standard image format: {suffix}")
    sha256 = sha256_file(path)
    size_bytes = path.stat().st_size
    try:
        loaded = load_standard_image(path)
    except ImageLoadError as exc:
        raise ImageDecodeError(str(exc)) from exc
    output = detector.analyze(loaded.image)
    return ImageAnalysis(path, sha256, size_bytes, loaded.mime_type, output)
