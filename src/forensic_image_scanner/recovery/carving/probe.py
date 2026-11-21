"""Capability probe for the system PhotoRec binary."""

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PhotoRecCapability:
    available: bool
    binary: Path | None
    version: str | None
    detail: str | None = None


def probe_photorec(
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> PhotoRecCapability:
    found = which("photorec")
    if not found:
        return PhotoRecCapability(False, None, None, "photorec command not found")
    binary = Path(found)
    try:
        result = runner(
            [str(binary), "/version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return PhotoRecCapability(
            False, binary, None, f"version probe failed: {type(exc).__name__}"
        )
    output = f"{result.stdout}\n{result.stderr}"
    match = re.search(r"PhotoRec\s+([0-9][^,\s]*)", output)
    if result.returncode != 0 or not match:
        return PhotoRecCapability(False, binary, None, "PhotoRec version probe failed")
    return PhotoRecCapability(True, binary, match.group(1))
