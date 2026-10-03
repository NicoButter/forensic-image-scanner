"""Optional read-only HEIF/HEIC loader."""

from pathlib import Path

from forensic_image_scanner.image_loader import LoadedImage, load_standard_image


def load_heif_image(path: Path) -> LoadedImage:
    """Load HEIF after lazily registering pillow-heif's decoder."""
    try:
        from pillow_heif import register_heif_opener
    except ImportError as exc:
        raise RuntimeError('HEIF support requires: pip install -e ".[heif]"') from exc

    register_heif_opener()
    return load_standard_image(path)
