"""Cancellable PhotoRec subprocess execution isolated from the workspace."""

import shutil
import subprocess
import threading
import time
from pathlib import Path


class PhotoRecError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


class PhotoRecRunner:
    def run(
        self,
        arguments: list[str],
        *,
        cwd: Path,
        log_path: Path,
        timeout: float,
        cancel: threading.Event,
        min_free_bytes: int = 64 * 1024 * 1024,
    ) -> int:
        with log_path.open("wb") as log:
            if shutil.disk_usage(cwd).free < min_free_bytes:
                raise PhotoRecError(
                    "FAILED_TARGET_FULL", "target free space safety threshold reached"
                )
            try:
                process = subprocess.Popen(arguments, stdout=log, stderr=log, cwd=cwd)
            except OSError as exc:
                raise PhotoRecError("PHOTOREC_NOT_AVAILABLE", str(exc)) from exc
            started = time.monotonic()
            while process.poll() is None:
                if cancel.wait(0.2):
                    _stop(process)
                    raise PhotoRecError("CANCELLED", "PhotoRec carving cancelled")
                if time.monotonic() - started >= timeout:
                    _stop(process)
                    raise PhotoRecError("TIMEOUT", "PhotoRec carving timed out")
                if shutil.disk_usage(cwd).free < min_free_bytes:
                    _stop(process)
                    raise PhotoRecError(
                        "FAILED_TARGET_FULL", "target free space safety threshold reached"
                    )
            return int(process.returncode or 0)


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
