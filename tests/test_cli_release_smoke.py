"""Entrypoint smoke tests do not invoke external forensic tools or models."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "arguments",
    [
        ["--help"],
        ["--version"],
        ["scan", "--help"],
        ["recover", "--help"],
        ["run", "--help"],
        ["acquire", "--help"],
        ["case", "--help"],
        ["validate-media", "--help"],
        ["detector", "--help"],
        ["model", "--help"],
    ],
)
def test_cli_help_commands_start_without_models(arguments):
    completed = subprocess.run(
        [sys.executable, "-m", "forensic_image_scanner.cli", *arguments],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0
    assert "Traceback" not in completed.stderr
    if arguments == ["--version"]:
        assert "0.1.0" in completed.stdout
    else:
        assert "usage:" in completed.stdout.casefold()


@pytest.mark.parametrize(
    "arguments",
    [
        ["acquire", "/dev/not-a-real-device", "--format", "invalid"],
        ["case", "info"],
    ],
)
def test_invalid_cli_arguments_fail_cleanly(arguments):
    completed = subprocess.run(
        [sys.executable, "-m", "forensic_image_scanner.cli", *arguments],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
        shell=False,
    )

    assert completed.returncode == 2
    assert "usage:" in completed.stderr.casefold()
    assert "Traceback" not in completed.stderr
