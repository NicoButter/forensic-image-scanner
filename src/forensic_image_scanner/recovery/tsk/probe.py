"""Capability probe for system-installed TSK tools."""

import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REQUIRED_TOOLS = ("mmls", "fsstat", "fls", "icat")
OPTIONAL_TOOLS = ("img_stat", "tsk_recover")


@dataclass(frozen=True, slots=True)
class TskCapability:
    available: bool
    version: str | None
    tools: dict[str, Path | None]
    missing_tools: tuple[str, ...]
    detail: str | None = None


def probe_tsk(
    which: Callable[[str], str | None] = shutil.which,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> TskCapability:
    tools = {
        name: Path(found) if (found := which(name)) else None
        for name in (*REQUIRED_TOOLS, *OPTIONAL_TOOLS)
    }
    missing = tuple(name for name in REQUIRED_TOOLS if tools[name] is None)
    if missing:
        return TskCapability(False, None, tools, missing, "required TSK commands are missing")
    try:
        completed = runner(
            [str(tools["fls"]), "-V"], capture_output=True, text=True, timeout=5, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return TskCapability(False, None, tools, (), f"version probe failed: {type(exc).__name__}")
    output = (completed.stdout or completed.stderr).strip()
    if completed.returncode != 0 or not output:
        return TskCapability(False, None, tools, (), "fls version probe failed")
    return TskCapability(True, output.splitlines()[0], tools, ())
