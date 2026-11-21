"""Bounded argument-array execution for TSK commands."""

import subprocess
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


class TskCommandError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code


@dataclass(frozen=True, slots=True)
class CommandResult:
    arguments: tuple[str, ...]
    stdout: str
    stderr: str
    returncode: int


class TskRunner:
    def run_text(self, arguments: Sequence[str], *, timeout: float) -> CommandResult:
        try:
            completed = subprocess.run(
                list(arguments), capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise TskCommandError("TIMEOUT", f"TSK command timed out after {timeout:g}s") from exc
        except OSError as exc:
            raise TskCommandError("TSK_NOT_AVAILABLE", str(exc)) from exc
        return CommandResult(
            tuple(arguments), completed.stdout, completed.stderr, completed.returncode
        )

    def extract(
        self,
        arguments: Sequence[str],
        destination: Path,
        *,
        timeout: float,
        cancel: threading.Event,
    ) -> CommandResult:
        with destination.open("wb") as output, tempfile.TemporaryFile() as error_output:
            try:
                process = subprocess.Popen(
                    list(arguments), stdout=output, stderr=error_output, text=False
                )
            except OSError as exc:
                raise TskCommandError("TSK_NOT_AVAILABLE", str(exc)) from exc
            elapsed = 0.0
            interval = 0.1
            while process.poll() is None:
                if cancel.wait(interval):
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    raise TskCommandError("CANCELLED", "recovery cancelled")
                elapsed += interval
                if elapsed >= timeout:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    raise TskCommandError("TIMEOUT", f"icat timed out after {timeout:g}s")
            error_output.seek(0)
            stderr = error_output.read().decode("utf-8", errors="replace")
        return CommandResult(tuple(arguments), "", stderr, int(process.returncode or 0))
