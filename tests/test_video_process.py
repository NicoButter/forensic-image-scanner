"""Owned ffmpeg lifecycle and sampling-bound tests without external binaries."""

import subprocess
import threading

import pytest

from forensic_image_scanner.pipeline.video import sample_video


@pytest.mark.parametrize(
    ("cancelled", "timeout", "message"),
    [
        (True, 30, "VIDEO_SAMPLING_CANCELLED"),
        (False, 0.1, "VIDEO_SAMPLING_TIMEOUT"),
    ],
)
def test_video_sampling_stops_owned_process(
    monkeypatch, tmp_path, cancelled, timeout, message
):
    import forensic_image_scanner.pipeline.video as video

    source = tmp_path / "source.mp4"
    source.write_bytes(b"fixture")
    destination = tmp_path / "frames"
    processes = []

    class Process:
        returncode = None

        def __init__(self, arguments, **kwargs):
            self.arguments = arguments
            self.kwargs = kwargs
            self.terminated = False
            processes.append(self)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def kill(self):
            self.returncode = -9

        def wait(self, timeout=None):
            return self.returncode

    monkeypatch.setattr(video.shutil, "which", lambda _: "/usr/bin/ffmpeg")
    monkeypatch.setattr(video.subprocess, "Popen", Process)
    cancel = threading.Event()
    if cancelled:
        cancel.set()

    with pytest.raises(InterruptedError if cancelled else TimeoutError, match=message):
        sample_video(
            source,
            destination,
            max_frames=3,
            cancel=cancel,
            timeout=timeout,
        )

    process = processes[0]
    assert process.terminated
    assert process.kwargs["shell"] is False
    assert process.kwargs["stdin"] is subprocess.DEVNULL
    assert process.kwargs["cwd"] == destination.resolve()
    assert process.arguments[process.arguments.index("-frames:v") + 1] == "3"
