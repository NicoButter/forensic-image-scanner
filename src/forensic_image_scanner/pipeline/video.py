"""Bounded video frame extraction for sampled analysis."""

import shutil
import subprocess
import threading
from pathlib import Path

DEFAULT_SAMPLE_SECONDS = 5.0
DEFAULT_MAX_FRAMES = 1000


def sample_video(
    source: Path,
    destination: Path,
    *,
    interval: float = DEFAULT_SAMPLE_SECONDS,
    max_frames: int = DEFAULT_MAX_FRAMES,
    cancel: threading.Event | None = None,
    timeout: float = 3600,
) -> list[Path]:
    """Sample into a caller-owned temporary directory using a child process."""
    if interval <= 0 or max_frames <= 0:
        raise ValueError("sampling interval and frame cap must be positive")
    binary = shutil.which("ffmpeg")
    if binary is None:
        raise RuntimeError("FFMPEG_NOT_AVAILABLE")
    destination.mkdir(parents=True, exist_ok=True)
    command = [
        binary,
        "-nostdin",
        "-v",
        "error",
        "-i",
        str(source),
        "-vf",
        f"fps=1/{interval}",
        "-frames:v",
        str(max_frames),
        "-y",
        str(destination / "frame-%06d.png"),
    ]
    cancel = cancel or threading.Event()
    with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as child:
        try:
            remaining = timeout
            while child.poll() is None:
                if cancel.wait(min(0.2, max(remaining, 0))):
                    raise InterruptedError("video sampling cancelled")
                remaining -= 0.2
                if remaining <= 0:
                    raise TimeoutError("video sampling timed out")
            if child.returncode:
                raise RuntimeError(f"ffmpeg exited with code {child.returncode}")
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
    return sorted(destination.glob("frame-*.png"))
