"""Bounded video frame extraction for sampled analysis."""

import logging
import shutil
import subprocess
import tempfile
import threading
from pathlib import Path

DEFAULT_SAMPLE_SECONDS = 5.0
DEFAULT_MAX_FRAMES = 1000
MAX_DIAGNOSTIC_BYTES = 4096
LOGGER = logging.getLogger(__name__)


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
    source = source.expanduser().resolve(strict=True)
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
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
    with tempfile.TemporaryFile() as stderr:
        with subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr,
            cwd=destination,
            shell=False,
        ) as child:
            try:
                remaining = timeout
                while child.poll() is None:
                    if cancel.wait(min(0.2, max(remaining, 0))):
                        raise InterruptedError("VIDEO_SAMPLING_CANCELLED")
                    remaining -= 0.2
                    if remaining <= 0:
                        raise TimeoutError("VIDEO_SAMPLING_TIMEOUT")
            finally:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
        if child.returncode:
            stderr_size = stderr.seek(0, 2)
            stderr.seek(max(0, stderr_size - MAX_DIAGNOSTIC_BYTES))
            diagnostic = stderr.read(MAX_DIAGNOSTIC_BYTES).decode("utf-8", errors="replace")
            diagnostic = diagnostic.replace(str(source), "<SOURCE>").replace(
                str(destination), "<OUTPUT>"
            )
            LOGGER.warning(
                "video sampling stage=ffmpeg error=FFMPEG_FAILED exit=%s detail=%s",
                child.returncode,
                diagnostic.strip()[:MAX_DIAGNOSTIC_BYTES],
            )
            raise RuntimeError(f"FFMPEG_FAILED: exit {child.returncode}")
    return sorted(destination.glob("frame-*.png"))
