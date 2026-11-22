"""Bounded ffprobe metadata validation."""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from forensic_image_scanner.media.models import MediaIntegrity, MediaRecord

LOGGER = logging.getLogger(__name__)
MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 4096


def validate_video(path: Path, record: MediaRecord, timeout: float = 30) -> None:
    binary = shutil.which("ffprobe")
    if binary is None:
        record.integrity = MediaIntegrity.UNSUPPORTED
        record.errors.append("FFPROBE_NOT_AVAILABLE")
        return
    try:
        source = path.resolve()
        command = [
            binary,
            "-v",
            "warning",
            "-show_entries",
            "format=format_name,duration:stream=codec_type,codec_name,width,height,duration,avg_frame_rate,r_frame_rate",
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            str(source),
        ]
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            result = subprocess.run(
                command,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout,
                check=False,
                shell=False,
                cwd=source.parent,
            )
            if os.fstat(stdout.fileno()).st_size > MAX_PROBE_OUTPUT_BYTES:
                record.errors.append("FFPROBE_OUTPUT_LIMIT")
                LOGGER.warning("media validation stage=ffprobe error=FFPROBE_OUTPUT_LIMIT")
                return
            stdout.seek(0)
            data = json.loads(stdout.read(MAX_PROBE_OUTPUT_BYTES + 1))
            stderr_size = os.fstat(stderr.fileno()).st_size
            stderr.seek(max(0, stderr_size - MAX_DIAGNOSTIC_BYTES))
            diagnostic = stderr.read(MAX_DIAGNOSTIC_BYTES).decode("utf-8", errors="replace")
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("streams"), list)
            or any(not isinstance(stream, dict) for stream in data["streams"])
            or not isinstance(data.get("format", {}), dict)
        ):
            record.errors.append("MALFORMED_FFPROBE_JSON")
            LOGGER.warning("media validation stage=ffprobe error=MALFORMED_FFPROBE_JSON")
            return
        streams = [s for s in data["streams"] if s.get("codec_type") == "video"]
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
        if diagnostic.strip():
            record.warnings.append(diagnostic.strip())
        record.integrity = (
            MediaIntegrity.PARTIAL
            if result.returncode or record.warnings or record.duration_seconds is None
            else MediaIntegrity.VALID
        )
        if record.duration_seconds is None:
            record.warnings.append("duration unavailable")
    except subprocess.TimeoutExpired:
        record.errors.append("FFPROBE_TIMEOUT")
        LOGGER.warning("media validation stage=ffprobe error=FFPROBE_TIMEOUT")
    except (OSError, ValueError, TypeError, ZeroDivisionError) as exc:
        code = (
            "MALFORMED_FFPROBE_JSON"
            if isinstance(exc, json.JSONDecodeError)
            else "FFPROBE_ERROR"
        )
        record.errors.append(code)
        LOGGER.warning("media validation stage=ffprobe error=%s", code)
