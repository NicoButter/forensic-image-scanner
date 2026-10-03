"""Optional read-only camera RAW loader."""

from pathlib import Path

from PIL import Image

from forensic_image_scanner.image_loader import LoadedImage


def load_raw_image(path: Path) -> LoadedImage:
    """Decode RAW data into an independent in-memory RGB representation."""
    try:
        import rawpy
    except ImportError as exc:
        raise RuntimeError('RAW support requires: pip install -e ".[raw]"') from exc

    with rawpy.imread(str(path)) as raw:
        rgb_array = raw.postprocess(output_bps=8)
    return LoadedImage(Image.fromarray(rgb_array, mode="RGB"), None, "RAW")
