# Third-party notices

This file records direct dependencies selected for the bootstrap project. Exact
installed versions are environment-specific; consult `pyproject.toml` and the
environment package inventory.

The administrative downloader uses Python's standard-library `urllib`; no new
third-party HTTP dependency is introduced. The FIS core is Apache-2.0 and
talks to the separately installed AGPL-3.0 NudeNet distribution over JSON.

| Component | Purpose | License | Notes |
| --- | --- | --- | --- |
| Pillow | standard image decoding | MIT-CMU | Mature project. |
| NumPy | numeric arrays | BSD-3-Clause plus bundled permissive notices | Review the distribution's bundled license file. |
| opencv-python-headless | headless OpenCV bindings | MIT packaging; Apache-2.0 OpenCV | Wheels include LGPL-2.1 FFmpeg and other third-party binaries; preserve bundled notices. |
| pillow-heif | optional HEIF decoding | BSD-3-Clause | Wheels bundle libheif/codecs; preserve their notices and re-check binary licensing when redistributing. |
| rawpy | optional RAW decoding | MIT | Wheels bundle LibRaw (LGPL-2.1 or CDDL); GPL demosaic packs are not included by upstream. |
| PyTorch | manually installed CPU Falconsai runtime | BSD-style | Use the official CPU wheel index; it is intentionally not in `.[models]` to avoid automatic CUDA installation on Linux. Preserve bundled notices. |
| Transformers | optional Falconsai adapter/runtime | Apache-2.0 | Hub helpers can download automatically; project code must use local-only mode. |
| Safetensors | optional model serialization | Apache-2.0 | Used to load a manually imported artifact. |
| ONNX Runtime | optional CPU runtime in NudeNet's separate environment | MIT | Installed only by explicit backend setup. |
| NudeNet 3.4.2 | optional external detector process | AGPL-3.0 distributed license | PyPI metadata says MIT. The pinned wheel carries AGPL-3.0 and is acquired upstream at opt-in. |
| NudeNet 320n and 640m | experimental ONNX weights, stored locally | AGPL-3.0 recorded by ONNX metadata | Each artifact has its own hash. Both have partial training provenance. |
| Falconsai/nsfw_image_detection | global classifier weights, stored locally | Apache-2.0 declared in model card | Dataset is proprietary and separate. Provenance status is partial. |
| OpenNSFW2 | evaluated, not installed | MIT | Deferred: requires GUI OpenCV alongside the conflicting headless distribution and introduces a download-oriented dependency chain. Model provenance and weights terms also need review. |
| pytest | tests | MIT | Development only. |
| Ruff | linting | MIT | Development only. |

Apache-2.0 compatibility here refers to the project's use of dependencies; it
does not replace compliance with each distribution's notices, dynamic-linking
terms, codec/patent considerations, or model-weight terms.
