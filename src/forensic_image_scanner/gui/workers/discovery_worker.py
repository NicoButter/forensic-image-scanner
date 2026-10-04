"""Qt discovery worker for read-only evidence discovery."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Signal

SUPPORTED_DISCOVERY_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
    ".heic",
    ".heif",
}


class DiscoveryWorker(QObject):
    """Scan a source directory for supported image files without reading file contents."""

    progress = Signal(str)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(self, source: str, recursive: bool = False, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.source = source
        self.recursive = recursive

    def run(self) -> None:
        try:
            path = Path(self.source)
            if not path.exists() or not path.is_dir():
                raise FileNotFoundError(f"Evidence directory not found: {self.source}")
            self.progress.emit("Scanning directory...")
            counts: dict[str, int] = {}
            total_files = 0
            directories = 0
            unsupported = 0
            errors = 0
            iterator = path.rglob("*") if self.recursive else path.iterdir()
            for item in iterator:
                if item.is_dir():
                    directories += 1
                    continue
                if not item.is_file():
                    unsupported += 1
                    continue
                total_files += 1
                suffix = item.suffix.lower()
                if suffix in SUPPORTED_DISCOVERY_EXTENSIONS:
                    format_name = suffix.lstrip(".").upper()
                    counts[format_name] = counts.get(format_name, 0) + 1
                else:
                    unsupported += 1
            summary = {
                "total_images": total_files,
                "directories_visited": directories,
                "unsupported_files": unsupported,
                "errors": errors,
                "counts": counts,
                "source": str(path),
            }
            self.completed.emit(summary)
        except OSError as exc:
            self.failed.emit(str(exc))
