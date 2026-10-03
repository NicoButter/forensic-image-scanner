"""Read-only loading and in-memory normalization for standard images."""

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, ImageOps, UnidentifiedImageError


class ImageLoadError(RuntimeError):
    """Raised when an image cannot be decoded safely."""


@dataclass(frozen=True, slots=True)
class LoadedImage:
    """An independently owned, normalized in-memory image."""

    image: Image.Image
    mime_type: str | None
    source_format: str | None


def load_standard_image(path: Path) -> LoadedImage:
    """Open an image read-only, apply EXIF orientation, and return an RGB copy."""
    try:
        with Image.open(path, mode="r") as opened:
            source_format = opened.format
            mime_type = Image.MIME.get(source_format or "")
            normalized = ImageOps.exif_transpose(opened).convert("RGB")
            normalized.load()
            independent_copy = normalized.copy()
    except (OSError, UnidentifiedImageError) as exc:
        raise ImageLoadError(f"Unable to decode image {path}: {exc}") from exc

    return LoadedImage(independent_copy, mime_type, source_format)
