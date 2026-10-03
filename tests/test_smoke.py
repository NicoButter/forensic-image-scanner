"""Bootstrap smoke tests."""

import subprocess
import sys


def test_package_imports() -> None:
    import forensic_image_scanner
    from forensic_image_scanner.detectors.base import Detector

    assert forensic_image_scanner.__version__ == "0.1.0"
    assert Detector.__name__ == "Detector"


def test_cli_help() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "forensic_image_scanner.cli", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert "forensic-image-scanner" in completed.stdout
    assert "scan" in completed.stdout
