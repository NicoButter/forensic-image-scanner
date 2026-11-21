"""System acquisition tools are optional and independently detected."""

from pathlib import Path

from forensic_image_scanner.acquisition import probe_acquisition_tools


def test_acquisition_tool_presence(monkeypatch):
    import forensic_image_scanner.acquisition.probe as probe

    tools = {
        "ewfacquire": "/usr/bin/ewfacquire",
        "ewfverify": None,
        "ddrescue": "/usr/bin/ddrescue",
    }
    monkeypatch.setattr(probe.shutil, "which", tools.get)
    result = probe_acquisition_tools()
    assert result.ewfacquire == Path("/usr/bin/ewfacquire")
    assert not result.e01_available and result.raw_available
