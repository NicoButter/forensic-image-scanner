# Model policy

No model may be enabled until its code and weights have been reviewed and the
following facts are recorded in `MODEL_PROVENANCE.md` and
`MODEL_LICENSES.md`:

- model name and exact version;
- canonical source URL and acquisition date;
- framework and runtime requirements;
- code license and the separate weights license;
- SHA-256 of every weights artifact;
- training-data provenance when available;
- known scope, biases, failure modes, and evaluation limitations;
- the local installation and update procedure.

Code licensing never implies that model weights or training data have the same
license. Ambiguous or missing permission for the intended use blocks inclusion.
Automatic runtime downloads are not permitted. Network access is allowed only
for the explicit administrative `model download` / `DOWNLOAD AND INSTALL`
operation. It accepts no user URL and uses immutable URLs from the audited manifest.

## Registry enforcement

Operational artifacts live under `models/<model-id>/`, outside the package and
ignored by Git. Each directory must contain a schema-v1 `manifest.json`. The
registry accepts only plain model IDs and filenames, validates the schema and
directory identity, rejects blocked statuses, checks existence and byte size,
and calculates SHA-256 with bounded-memory reads for every required artifact.

Allowed status values are `verified`, `partial`, `blocked_provenance`, and
`blocked_license`. Both blocked states are hard failures. `partial` requires an
explicitly documented residual risk and may be further restricted by the
detector implementation. Detectors receive only a `VerifiedModel`; they must
not select paths, call download helpers, or substitute packaged defaults.

The controlled workflow is:

```text
explicit download or directory import -> temporary files -> size and SHA-256
verification -> atomic controlled model directory -> registry validation
-> offline inference
```

Framework loaders must use local paths, offline mode, and their equivalent of
`local_files_only=True`. The Falconsai adapter also sets `HF_HUB_OFFLINE=1`,
`TRANSFORMERS_OFFLINE=1`, and `HF_HUB_DISABLE_TELEMETRY=1` before loading
Transformers. Network isolation during analysis is a supported and expected
deployment mode.

Download integrity and training-data provenance are separate. A matching
SHA-256 proves artifact identity only; it never changes Falconsai's `partial`
status. Imports reject symlinks and require declared regular files within the
selected directory.

## Current decisions

- NudeNet 320n: `blocked_provenance`. Package licensing is contradictory and
  the training dataset/procedure is not documented.
- Falconsai/nsfw_image_detection: `partial`. It is the first implemented
  single-image detector because the repository declares Apache-2.0 and
  publishes stable hashes, but its proprietary dataset is only described at a
  high level. The detector only returns `normal`/`nsfw` probabilities and is
  never a legal conclusion.

## Currently deferred engines

OpenNSFW2 is not part of an installable extra yet. Its published dependency on
`opencv-python` conflicts with this project's `opencv-python-headless` base
(both install the `cv2` namespace), and its dependency chain includes a network
downloader. Integration requires an upstream packaging change or a documented,
reproducible installation that preserves the no-network runtime boundary.
