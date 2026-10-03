"""Standard image loader tests using generated, non-sensitive data."""

from PIL import Image

from forensic_image_scanner.image_loader import load_standard_image


def test_load_standard_image_returns_independent_rgb_copy(tmp_path) -> None:
    source = tmp_path / "synthetic.png"
    Image.new("L", (3, 2), color=127).save(source)
    before = source.read_bytes()

    loaded = load_standard_image(source)

    assert loaded.image.mode == "RGB"
    assert loaded.image.size == (3, 2)
    assert loaded.mime_type == "image/png"
    assert loaded.source_format == "PNG"
    assert source.read_bytes() == before
