"""NudeNet adapter boundary (implementation planned for a later milestone)."""

from PIL import Image

from forensic_image_scanner.detectors.base import Detector, DetectorOutput
from forensic_image_scanner.models.manifest import ProvenanceStatus
from forensic_image_scanner.models.registry import VerifiedModel

MODEL_STATUS = ProvenanceStatus.BLOCKED_PROVENANCE


class NudeNetDetector(Detector):
    """Future local NudeNet adapter with no implicit model resolution."""

    def __init__(self, model: VerifiedModel) -> None:
        self.model = model

    def analyze(self, image: Image.Image) -> DetectorOutput:
        """Reject use until model provenance and mapping are implemented."""
        del image
        raise NotImplementedError(
            "NudeNet inference is disabled; the audited 320n model has blocked provenance"
        )
