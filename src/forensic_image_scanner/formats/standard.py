"""Standard format identification."""

from pathlib import Path

STANDARD_IMAGE_SUFFIXES = frozenset({".bmp", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"})


def is_standard_image(path: Path) -> bool:
    """Return whether a path has a supported standard-image suffix."""
    return path.suffix.casefold() in STANDARD_IMAGE_SUFFIXES
