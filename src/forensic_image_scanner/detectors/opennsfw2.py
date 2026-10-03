"""OpenNSFW2 adapter boundary (implementation planned for a later milestone)."""

from PIL import Image

from forensic_image_scanner.detectors.base import Detector, DetectorOutput
from forensic_image_scanner.models.registry import VerifiedModel


class OpenNsfw2Detector(Detector):
    """Future local OpenNSFW2 adapter with no implicit model resolution."""

    def __init__(self, model: VerifiedModel) -> None:
        self.model = model

    def analyze(self, image: Image.Image) -> DetectorOutput:
        """Reject use until model provenance and mapping are implemented."""
        del image
        raise NotImplementedError("OpenNSFW2 inference is not implemented yet")
