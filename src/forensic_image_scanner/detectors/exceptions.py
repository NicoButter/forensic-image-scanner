"""Expected detector and image-analysis failures."""


class DetectorError(RuntimeError):
    """Base class for expected detector failures."""


class UnsupportedImageError(DetectorError):
    """Raised for an image format unsupported by the selected detector."""


class ImageDecodeError(DetectorError):
    """Raised when a supplied image cannot be decoded safely."""


class InferenceError(DetectorError):
    """Raised when local model initialization or inference fails."""
