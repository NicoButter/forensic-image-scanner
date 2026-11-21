"""Bounded ffprobe metadata validation."""

import json
import shutil
import subprocess
from pathlib import Path

from forensic_image_scanner.media.models import MediaIntegrity, MediaRecord


def validate_video(path: Path, record: MediaRecord, timeout: float = 30) -> None:
    binary = shutil.which("ffprobe")
    if binary is None:
        record.integrity = MediaIntegrity.UNSUPPORTED
        record.errors.append("FFPROBE_NOT_AVAILABLE")
        return
    try:
        result = subprocess.run(
            [binary, "-v", "warning", "-show_format", "-show_streams", "-of", "json", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
        data = json.loads(result.stdout)
        streams = [s for s in data.get("streams", []) if s.get("codec_type") == "video"]
        record.video_stream_count = len(streams)
        info = data.get("format", {})
        record.actual_format = info.get("format_name")
        if not streams:
            record.errors.append("NO_VIDEO_STREAM")
            return
        stream = streams[0]
        record.codec = stream.get("codec_name")
        record.width, record.height = stream.get("width"), stream.get("height")
        if not record.codec or not record.width or not record.height:
            record.errors.append("UNUSABLE_VIDEO_STREAM")
            return
        duration = info.get("duration") or stream.get("duration")
        if duration is not None:
            record.duration_seconds = float(duration)
        rate = stream.get("avg_frame_rate") or stream.get("r_frame_rate")
        if rate:
            numerator, _, denominator = rate.partition("/")
            record.frame_rate = float(numerator) / float(denominator or 1)
        if result.stderr.strip():
            record.warnings.append(result.stderr.strip())
        record.integrity = (
            MediaIntegrity.PARTIAL
            if result.returncode or record.warnings or record.duration_seconds is None
            else MediaIntegrity.VALID
        )
        if record.duration_seconds is None:
            record.warnings.append("duration unavailable")
    except (subprocess.TimeoutExpired, OSError, ValueError, TypeError, ZeroDivisionError) as exc:
        record.errors.append(f"FFPROBE_ERROR: {exc}")
