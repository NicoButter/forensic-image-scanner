"""Central candidate extension policy for filesystem recovery."""

from pathlib import PurePath

from forensic_image_scanner.recovery.models import MediaKind

IMAGE_EXTENSIONS = frozenset(
    {
        ".jpg",
        ".jpeg",
        ".jpe",
        ".png",
        ".webp",
        ".gif",
        ".bmp",
        ".tif",
        ".tiff",
        ".heic",
        ".heif",
        ".avif",
        ".dng",
        ".cr2",
        ".cr3",
        ".nef",
        ".arw",
        ".raf",
        ".orf",
        ".rw2",
    }
)
VIDEO_EXTENSIONS = frozenset(
    {
        ".mp4",
        ".m4v",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".mpg",
        ".mpeg",
        ".wmv",
        ".3gp",
        ".3g2",
        ".mts",
        ".m2ts",
        ".ts",
        ".vob",
    }
)


def candidate_media_kind(name: str) -> MediaKind | None:
    extension = PurePath(name).suffix.casefold()
    if extension in IMAGE_EXTENSIONS:
        return MediaKind.IMAGE
    if extension in VIDEO_EXTENSIONS:
        return MediaKind.VIDEO
    return None
