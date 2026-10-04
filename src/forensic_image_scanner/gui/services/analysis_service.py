"""Service layer for analysis orchestration and future worker integration."""

from __future__ import annotations

from pathlib import Path

SUPPORTED_EXTENSIONS = {
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


class AnalysisService:
    """Read-only source discovery service for the GUI."""

    def discover_files(self, source: str | Path, recursive: bool = False) -> dict[str, object]:
        """Return candidate files and counts without modifying or hashing the evidence."""
        path = Path(source)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Evidence directory not found: {source}")

        counts: dict[str, int] = {}
        total_images = 0
        directories_visited = 0
        unsupported_files = 0
        iterator = path.rglob("*") if recursive else path.iterdir()

        for candidate in iterator:
            if candidate.is_dir():
                directories_visited += 1
                continue
            if not candidate.is_file():
                unsupported_files += 1
                continue
            total_images += 1
            suffix = candidate.suffix.lower()
            if suffix in SUPPORTED_EXTENSIONS:
                label = suffix.lstrip(".").upper()
                counts[label] = counts.get(label, 0) + 1
            else:
                unsupported_files += 1

        return {
            "source": str(path),
            "total_images": total_images,
            "directories_visited": directories_visited,
            "unsupported_files": unsupported_files,
            "errors": 0,
            "counts": counts,
        }

    def current_analysis_summary(self) -> dict[str, str | int]:
        """Return a compact summary for the home and analyze screens."""
        return {
            "files_discovered": 0,
            "total_size": 0,
            "status": "No analysis session created yet.",
        }
