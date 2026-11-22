"""Execution of one owned child process, with cooperative cancellation."""

import os
import stat
import subprocess
import threading
from pathlib import Path


class AcquisitionCancelled(Exception):
    """The user cancelled the owned process."""


def run_owned(arguments: list[str], log_path: Path, cancel: threading.Event) -> int:
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
    fd = os.open(log_path, flags, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("unsafe acquisition log")
    with os.fdopen(fd, "ab") as log:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            cwd=log_path.parent,
            shell=False,
        )
        try:
            while process.poll() is None:
                if cancel.wait(0.2):
                    raise AcquisitionCancelled("acquisition cancelled")
            return int(process.returncode or 0)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def tool_help(binary: Path) -> str:
    result = subprocess.run(
        [str(binary), "-h"], capture_output=True, text=True, timeout=10, check=False
    )
    return result.stdout + result.stderr


def tool_version(binary: Path) -> str | None:
    try:
        result = subprocess.run(
            [str(binary), "-V"], capture_output=True, text=True, timeout=10, check=False
        )
        text = (result.stdout + result.stderr).strip()
        return text.splitlines()[0] if text else None
    except (OSError, subprocess.SubprocessError):
        return None
