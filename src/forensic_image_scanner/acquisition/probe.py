"""Discover system acquisition tools without installing or invoking them."""

import shutil
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AcquisitionTools:
    ewfacquire: Path | None
    ewfverify: Path | None
    ddrescue: Path | None

    @property
    def e01_available(self) -> bool:
        return self.ewfacquire is not None and self.ewfverify is not None

    @property
    def raw_available(self) -> bool:
        return self.ddrescue is not None


def probe_acquisition_tools() -> AcquisitionTools:
    """Locate optional tools; later acquisition must probe their actual options."""
    paths = (shutil.which(name) for name in ("ewfacquire", "ewfverify", "ddrescue"))
    acquire, verify, rescue = (Path(path) if path else None for path in paths)
    return AcquisitionTools(acquire, verify, rescue)
