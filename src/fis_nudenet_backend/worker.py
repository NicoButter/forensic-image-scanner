"""Standalone JSON-lines bridge for the separately installed NudeNet distribution."""

import hashlib
import json
import socket
import sys
from importlib.metadata import version
from pathlib import Path


def forbid_network(event, args):
    if event in {"socket.getaddrinfo", "socket.connect"} or (
        event == "socket.__new__" and args[1] in {socket.AF_INET, socket.AF_INET6}
    ):
        raise PermissionError("Network is disabled for the NudeNet worker")


def main():
    artifact, expected_sha256, size, source = sys.argv[1:]
    root = Path(source).resolve(strict=True)
    sys.addaudithook(forbid_network)
    import cv2
    import numpy as np
    import onnxruntime

    onnxruntime.disable_telemetry_events()
    from nudenet import NudeDetector

    model = Path(artifact)
    payload = model.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_sha256:
        raise ValueError("Unexpected model SHA-256")
    detector = NudeDetector(model_path=payload, inference_resolution=int(size))
    del payload
    health = {
        "status": "ready",
        "backend": "nudenet",
        "backend_version": version("nudenet"),
        "model": model.stem,
        "model_sha256": digest,
        "license": "AGPL-3.0",
    }
    for line in iter(lambda: sys.stdin.buffer.readline(65537), b""):
        if len(line) > 65536:
            return
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or type(request.get("schema_version")) is not int:
                raise ValueError
            if request["schema_version"] != 1:
                raise ValueError
            operation = request.get("operation")
            if operation == "health" and set(request) == {"schema_version", "operation"}:
                response = health
            elif operation == "analyze" and set(request) == {
                "schema_version",
                "operation",
                "image_path",
            }:
                candidate = request["image_path"]
                if not isinstance(candidate, str):
                    raise ValueError
                path = Path(candidate)
                if not path.is_absolute() or path.is_symlink():
                    raise ValueError
                path = path.resolve(strict=True)
                if not path.is_relative_to(root) or not path.is_file():
                    raise ValueError
                encoded_image = np.frombuffer(path.read_bytes(), dtype=np.uint8)
                image = cv2.imdecode(encoded_image, cv2.IMREAD_COLOR)
                if image is None:
                    raise ValueError
                detections = detector.detect(image)
                response = {
                    "status": "ok",
                    "detections": [
                        {"class": row["class"], "confidence": row["score"], "box": row["box"]}
                        for row in detections
                    ],
                }
            else:
                raise ValueError
            encoded = json.dumps({"schema_version": 1, **response}, allow_nan=False)
        except Exception:
            encoded = '{"schema_version":1,"status":"error","error":"NudeNet request failed"}'
        print(encoded, flush=True)


if __name__ == "__main__":
    main()
