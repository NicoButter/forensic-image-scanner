"""Service layer for analysis orchestration and future worker integration."""

from __future__ import annotations

from pathlib import Path


class AnalysisService:
    """Placeholder orchestration service; it keeps the GUI decoupled from the core."""

    def discover_files(self, source: str | Path, recursive: bool = False) -> list[str]:
        """Return candidate files without scanning or hashing the evidence itself."""
        path = Path(source)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Evidence directory not found: {source}")

        iterator = path.rglob("*") if recursive else path.iterdir()
        files = sorted(
            str(candidate)
            for candidate in iterator
            if candidate.is_file()
            and candidate.suffix.lower()
            in {".jpg", ".jpeg", ".png", ".webp", ".heic", ".raw"}
        )
        return files

    def current_analysis_summary(self) -> dict[str, str | int]:
        """Return a compact summary for the home and analyze screens."""
        return {
            "files_discovered": 0,
            "total_size": 0,
            "status": "No analysis session created yet.",
        }
