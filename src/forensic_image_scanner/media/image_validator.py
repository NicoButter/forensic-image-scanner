"""Decode recovered images without changing them."""

from pathlib import Path

from PIL import Image, ImageFile, UnidentifiedImageError

from forensic_image_scanner.media.models import MediaIntegrity, MediaRecord

RAW_EXTENSIONS = {".dng", ".cr2", ".cr3", ".nef", ".arw", ".raf", ".orf", ".rw2"}
FORMATS = {"JPEG": {".jpg", ".jpeg", ".jpe"}, "TIFF": {".tif", ".tiff"}}


def validate_image(path: Path, record: MediaRecord) -> None:
    ext = record.candidate_extension.lower()
    try:
        with Image.open(path) as image:
            record.actual_format = image.format
            record.width, record.height = image.size
            image.verify()
        with Image.open(path) as image:
            image.load()
        record.integrity = MediaIntegrity.VALID
    except (OSError, ValueError, SyntaxError, UnidentifiedImageError) as exc:
        if ext in {".heic", ".heif", ".avif"}:
            try:
                from forensic_image_scanner.formats.heif import load_heif_image

                loaded = load_heif_image(path)
                record.width, record.height = loaded.image.size
                record.actual_format = loaded.source_format
                record.integrity = MediaIntegrity.VALID
            except ImportError:
                record.integrity = MediaIntegrity.UNSUPPORTED
                record.errors.append("HEIF_DECODER_NOT_AVAILABLE")
            except RuntimeError:
                record.integrity = MediaIntegrity.UNSUPPORTED
                record.errors.append("HEIF_DECODER_NOT_AVAILABLE")
            except Exception as error:
                record.errors.append(str(error))
        elif ext in RAW_EXTENSIONS:
            try:
                from forensic_image_scanner.formats.raw import load_raw_image

                loaded = load_raw_image(path)
                record.width, record.height = loaded.image.size
                record.actual_format = "RAW"
                record.integrity = MediaIntegrity.VALID
            except (ImportError, RuntimeError):
                record.integrity = MediaIntegrity.UNSUPPORTED
                record.errors.append("RAW_DECODER_NOT_AVAILABLE")
            except Exception as error:
                record.errors.append(str(error))
        else:
            record.errors.append(str(exc))
            # Pillow can sometimes decode truncated image pixels even when verify fails.
            old = ImageFile.LOAD_TRUNCATED_IMAGES
            try:
                ImageFile.LOAD_TRUNCATED_IMAGES = True
                with Image.open(path) as image:
                    image.load()
                    record.actual_format = image.format
                    record.width, record.height = image.size
                record.integrity = MediaIntegrity.PARTIAL
                record.warnings.append("incomplete image decoded with truncation enabled")
            except (OSError, ValueError, SyntaxError):
                pass
            finally:
                ImageFile.LOAD_TRUNCATED_IMAGES = old
    if record.actual_format:
        expected = FORMATS.get(record.actual_format.upper(), {f".{record.actual_format.lower()}"})
        if ext not in expected:
            record.warnings.append("candidate extension differs from decoded format")
