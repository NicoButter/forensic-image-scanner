# Forensic Image Scanner

Forensic Image Scanner is an early-stage, open source toolkit for local image
content triage across large collections. The intended workflow identifies image
files, hashes original evidence, creates independent normalized representations,
runs local nudity/potential explicit-content models, and emits auditable reports.

> **Experimental:** sequential recursive scanning is available with the exact
> audited Falconsai artifacts. Triage thresholds are initial project policy,
> not model classes or legal conclusions. All findings require human review.

## Privacy and evidence safety

- Processing is designed to run completely locally.
- Images, hashes, metadata, and results are not uploaded.
- Original evidence is treated as read-only and is never converted in place.
- SHA-256 is computed from the original bytes using block reads.
- Normalization occurs on an independent in-memory RGB representation.
- No telemetry, cloud APIs, web framework, or database is included.

See [forensic principles](docs/forensic_principles.md) for the complete boundary.

## Requirements and installation

Use Python 3.11 or newer.

## Quick Start

After cloning the repository, run the desktop application with:

```bash
git clone https://github.com/NicoButter/forensic-image-scanner.git
cd forensic-image-scanner
chmod +x start.sh
./start.sh
```

`start.sh` creates or reuses the local `.venv`, installs the editable project
with its GUI extra when needed, and launches the desktop interface. It does not
download model weights. Use `./start.sh --check` to prepare and verify the
environment without opening the GUI, `./start.sh --repair` to reinstall the
editable package and GUI extra, or `./start.sh --dev` to include development
dependencies. The launcher requires Python 3.11 or newer.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
```

Optional features are independent:

```bash
python -m pip install -e ".[heif]"
python -m pip install -e ".[raw]"
python -m pip install -e ".[models]"
python -m pip install -e ".[gui]"
python -m pip install -e ".[all]"
python -m pip install -e ".[dev]"
```

## Graphical Interface

The project includes an optional Qt desktop interface designed for offline,
read-only evidence triage. It is intentionally separate from the core analysis
pipeline and uses the same local model registry, policy, and forensic boundaries.

```bash
python -m pip install -e ".[gui]"
forensic-image-scanner-gui
```

The graphical interface starts without internet access, never requires a cloud
API, keeps the evidence directory read-only, and uses safe review mode by
default to blur sensitive thumbnails until the reviewer explicitly reveals them.
The application can also be launched directly with:

```bash
python -m forensic_image_scanner.gui
```

### Source, target, operation

The **New Operation** page makes the forensic workflow explicit:

1. Choose a source: a media directory, forensic-image candidate, or Linux
   physical device reported by `lsblk`.
2. Choose a separate writable target for findings, reports, logs, and future
   recovered media.
3. Choose Analyze, Recover, or Recover + Analyze.

FIS-011 introduces this recovery workflow architecture. **Directory + Analyze**
and **Forensic image + Recover** are executable when their required local engines
are ready. Forensic-image recovery can use The Sleuth Kit, PhotoRec, or both;
Recover + Analyze runs the catalog and selected detector profile after recovery.
Physical-device recovery first acquires an image using separately installed
libewf or GNU ddrescue. FIS never infers that
an image format is valid from its extension, mounts or unmounts a selected
device, or writes to it during discovery or recovery.

### Forensic cases

Create a persistent case before an operation when a stable identity, audit
trail, and consolidated report are required:

```bash
forensic-image-scanner case create /cases/incident-001 \
  --case-number INC-001 --title "Evidence review" --examiner "Examiner"
forensic-image-scanner acquire /dev/sdX --case /cases/incident-001 --format e01
forensic-image-scanner case info /cases/incident-001
forensic-image-scanner case report /cases/incident-001
forensic-image-scanner case complete /cases/incident-001
```

`--case CASE_DIR` is also available on `scan`, `recover`, and `run`; it uses the
existing case directory as the operation target. Case metadata is persisted in
`case.json`, audit events append to `logs/audit.jsonl`, and consolidated JSON
and offline HTML reports are written under `reports/`. The report requires
human review, treats triage labels as prioritization rather than legal
conclusions, and describes video analysis as sampled rather than exhaustive.
Completed cases must be explicitly reopened with `case reopen CASE_DIR` before
another operation. Completion does not make files immutable at the filesystem
level.

### Filesystem-aware deleted-media recovery

FIS can recover deleted image and video candidates from a forensic image when
filesystem metadata survives and the system-installed The Sleuth Kit provides
`mmls`, `fsstat`, `fls`, and `icat`. FIS does not download or install TSK.

```bash
forensic-image-scanner inspect-source /evidence/case.dd
forensic-image-scanner inspect-source /evidence/case.dd --json
forensic-image-scanner recover /evidence/case.dd --target /cases/FIS-001
forensic-image-scanner recover /evidence/case.dd --target /cases/FIS-002 \
  --filesystem-only --images-only
```

The backend inspects partition layouts and filesystems, enumerates deleted
entries, selects candidate image/video extensions, and streams `icat -r` output
into target-owned temporary files. Non-empty output is size-checked, hashed with
SHA-256, and atomically finalized under `recovered/filesystem/`. Original TSK
metadata and paths are preserved in `reports/recovery.json`; CSV and a structured
recovery log are also created.

Reallocated entries are skipped by default. An extension is only a candidate
type, not proof of valid media. Files missing usable filesystem metadata may be
recoverable through the separate PhotoRec carving path. Physical-device recovery
requires acquisition before recovery.

### Raw multimedia carving

FIS can invoke a separately installed system `photorec` to carve image/video
signatures from forensic images. FIS does not install or vendor PhotoRec. The
default `recover` command uses both available engines and both media kinds; use
`--filesystem-only` or `--carve-only`, and `--images-only` or `--videos-only`,
to narrow the operation.

```bash
forensic-image-scanner recover /evidence/case.dd --target /cases/FIS-003 \
  --carve-only --videos-only
```

TSK and PhotoRec have different evidentiary semantics: TSK recovers through
surviving filesystem metadata, while PhotoRec finds byte signatures and cannot
establish an original filename, path, or metadata address. Carving records those
fields as `UNKNOWN`, applies basic non-zero and containment checks, hashes every
accepted artifact with SHA-256, and writes it under
`recovered/carved/volume-NN/{images,videos}`. Identical TSK and PhotoRec output is
stored once while both provenance records remain in `recovery.json` and CSV.

When FIS has a recognized NTFS, FAT12/16/32, or Ext2/3/4 volume, it requests
PhotoRec free-space scanning. Otherwise it reports and performs whole-space
scanning; it never describes that result as deleted-only. PhotoRec signature
families can be broader than FIS's media allowlist, so non-media output is
discarded during normalization. Carved media undergoes the same validation as
filesystem-recovered media; validation cannot certify complete video playback.

Recovered artifacts are validated after recovery and cataloged by SHA-256 in
`reports/media_catalog.json` and `reports/media_catalog.csv`. Recovery provenance
remains separate from decoder integrity. Rebuild the catalog without recovery:

```bash
forensic-image-scanner validate-media /cases/FIS-003
```

Images use Pillow and optional HEIF/RAW decoders; video metadata uses the
system `ffprobe` when available. Validation does not alter recovered files.

The `models` extra installs Transformers and Safetensors. On Linux, install a
CPU-only PyTorch wheel separately so `pip install -e ".[models]"` never pulls
CUDA components:

```bash
python -m pip install --index-url https://download.pytorch.org/whl/cpu \
  "torch==2.14.1+cpu"
```

NudeNet 3.4.2 is an optional experimental, separately installed AGPL-3.0
backend. The FIS core remains Apache-2.0. Both NudeNet variants have partial
training provenance. See [Model licenses](MODEL_LICENSES.md) and
[Model provenance](MODEL_PROVENANCE.md) for the audit and artifact identities.
OpenNSFW2 remains deferred because of its GUI OpenCV dependency.

## Installing a model

Model installation is an explicit administrative operation. In the GUI use:

```text
Models & Detectors → Falconsai NSFW Image Detection → Download and Install
```

The downloader obtains only files declared at immutable revision
`96cb0d0342c7afb80cab76ecc58b265fa44da256`, streams them to temporary files,
verifies byte size and SHA-256, then installs them atomically:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `model.safetensors` | 343,223,968 | `97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830` |
| `config.json` | 724 | `cd8c0a19566f199b5c64da402f1d6a9daf80d094fe6536befb060a2cc59449c2` |
| `preprocessor_config.json` | 325 | `a34861a24e781942424ad790b82bc99348404a2e64ea882de88c40905851698d` |

The CLI uses the same installation service:

```bash
forensic-image-scanner model download falconsai-nsfw-image-detection
```

For offline transfer, put all three files in one directory. Symlinks are rejected:

```bash
forensic-image-scanner model import falconsai-nsfw-image-detection /admin-transfer/falconsai
```

Directory precedence is deterministic: `--model-dir`, then
`FORENSIC_IMAGE_SCANNER_MODEL_DIR`, then the platform data directory. The
import never overwrites an existing model directory.

```bash
forensic-image-scanner model list --model-dir /controlled/models
forensic-image-scanner model verify falconsai-nsfw-image-detection --model-dir /controlled/models
forensic-image-scanner model remove falconsai-nsfw-image-detection --model-dir /controlled/models
forensic-image-scanner model info falconsai-nsfw-image-detection --model-dir /controlled/models
forensic-image-scanner analyze image.jpg \
  --detector falconsai-nsfw-image-detection \
  --model-dir /controlled/models
```

Use `--json` with `analyze` for structured stdout. The detector uses only
local paths, `local_files_only=True`, a CPU device, Safetensors, and offline
Hugging Face/Transformers environment flags. It classifies only `normal` and
`nsfw`; neither label determines illegality or replaces human review.

Cryptographic verification proves only that downloaded bytes match the audited
revision. It does not certify training-data provenance; Falconsai remains
`partial`. NudeNet also retains partial training provenance after verification.
Analysis remains offline after installation.

## CLI

```bash
forensic-image-scanner --help
forensic-image-scanner scan /path/to/evidence \
  --output /path/to/reports \
  --model falconsai-nsfw-image-detection \
  --recursive
```

The batch service processes one supported image at a time, hashes original
bytes, decodes in memory, performs offline CPU inference, and atomically writes
`analysis.json` plus spreadsheet-safe `analysis.csv`. A corrupt image becomes
an error result and does not abort the remaining directory.

## Analysis profiles and optional NudeNet

Use **Models & Detectors → Install Backend**, review the AGPL-3.0 and provenance
notice, and select **Install**. The CLI equivalent is an explicit administrative
operation. A base Python with CPU ONNX Runtime wheels is required. Set
`FORENSIC_IMAGE_SCANNER_NUDENET_PYTHON` for the GUI or pass `--python` to the
first CLI install if the core Python is unsupported by ONNX Runtime.

```bash
forensic-image-scanner detector install --variant 320n --python /usr/bin/python3.12
forensic-image-scanner detector install --variant 640m
forensic-image-scanner detector status --variant 640m
forensic-image-scanner scan /path/to/evidence --recursive --output /path/to/reports \
  --profile combined --variant 640m
```

The installer checks the pinned wheel and ONNX bytes against their declared
size and SHA-256, creates an isolated environment under the configured
model-data root, and persists opt-in after a successful health check. Keep that
directory outside the Git repository. Use `detector disable` or `detector enable`
with `--variant` to manage a registered backend.

The GUI recommends **Combined Detection** when both detectors are ready.
**Falconsai Only** remains the default CLI profile and keeps the global NSFW
workflow. **NudeNet Only** uses qualifying exposed-anatomy detections and leaves
Falconsai score fields empty. **Combined Detection** uses anatomically
global scores and anatomical evidence. A Falconsai `HIGH` remains `HIGH` when
NudeNet finds no qualifying anatomy. An eligible detection at or above
0.85 can raise a Falconsai `REVIEW` to `HIGH`. If NudeNet fails, Combined keeps
Falconsai's baseline priority and records a backend error. The JSON preserves
each detector's results, NudeNet boxes as `[x, y, width, height]`, and triage
reasons. Safe Review displays metadata and keeps sensitive previews hidden.

## Explicit post-analysis export

Results can be selected in the GUI and exported only after analysis completes.
`EXPORT SELECTED` copies each selected, non-error result into
`<report-output>/exported/<TRIAGE>/<relative-path>`, verifies the destination
SHA-256 against the analysis hash, and atomically finalizes the copy. The source
file is never modified, renamed, or opened as a preview. `analysis.csv`,
`analysis.json`, and `audit.log` record the transfer result.

Sources default to **Evidence** mode, where moving is disabled. An operator may
explicitly declare a source a **Working copy**; only then does `MOVE SELECTED`
become available. A move is still a verified copy followed by source deletion,
never a direct `shutil.move`; a deletion failure is retained and reported as
`MOVE_PARTIAL`.

## Review priority

Falconsai returns probabilities for `normal` and `nsfw`. The project applies a
separate experimental policy to the raw NSFW probability. `LOW`, `REVIEW`, and
`HIGH` express review priority and carry no legal conclusion.

| Review priority | Raw NSFW probability |
| --- | --- |
| LOW | Below 0.60 |
| REVIEW | At least 0.60 and below 0.85 |
| HIGH | At least 0.85 |

The Results page shows `HIGH` and `REVIEW` by default, ordered by descending NSFW
score. **Show All Results** reveals all categories, including `LOW` and `ERROR`.
**Show Relevant Only** restores the default view. The summary counts every
processed record under **analyzed** and counts `HIGH` plus `REVIEW` under
**require review**. `analysis.json` and `analysis.csv` retain all rows, including
the categories hidden by the GUI, and preserve the original scores.

## Offline calibration

Use a local corpus containing only legal, authorized material. Keep it outside
version control. Put expected `normal` images in `normal/` and expected `nsfw`
images in `nsfw/` under the corpus root. Both subdirectories are required.
Supported images can be organized recursively.

```bash
forensic-image-scanner calibrate /path/to/calibration-corpus \
  --model falconsai-nsfw-image-detection \
  --output calibration-report.json
forensic-image-scanner calibrate --synthetic-controls
```

Calibration uses the installed, verified detectors and runs offline.
Repeat with `--profile falconsai`, `--profile nudenet`, and `--profile combined`,
selecting `--variant 320n` or `--variant 640m` for the NudeNet profiles to
compare all five configurations. Policy metrics count `REVIEW` and `HIGH` as
positive. The single-detector profiles also report threshold metrics from 0.50
through 0.95 in steps of 0.05, using the global probability or maximum
qualifying class score. Combined reports its decision metrics directly. An inclusive threshold assigns
an image to the binary `nsfw` class. The per-file `predicted_class` in the optional JSON uses
0.50 for a single detector and the priority decision for Combined. The JSON
records available raw detector results, expected class, relative path, model
revision and SHA-256, and the full sweep. Unreadable files are recorded as errors
and excluded from metrics. A run with file errors exits with code 6 and still
reports the scored rows. Undefined ratios appear as `—` in the terminal and
`null` in JSON. Choose a new output filename outside the corpus and model
directory. Calibration leaves the corpus and the production policy intact.

Synthetic controls provide a repeatable check on simple negative images. A
representative labelled corpus is needed to estimate practical false-positive
and false-negative rates. See [FIS-008 · CAL-01](docs/iterations/FIS-008-CAL-01.md)
for the initial measurements.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

Tests create synthetic, non-sensitive images and require no network. To run the
optional real-model integration test and print the synthetic scores, install
Falconsai locally and run `pytest -m model -s`. Run `pytest -m nudenet` with
the installed variants to check the real isolated runtime. The tests use the same model
directory resolution as the CLI, including `FORENSIC_IMAGE_SCANNER_MODEL_DIR`.

## Project layout

```text
src/forensic_image_scanner/
  cli.py                 command-line boundary
  analysis_service.py    sequential directory orchestration
  scanner.py             compatibility delegation boundary
  hashing.py             streaming SHA-256
  image_loader.py        standard read-only image loading
  analysis.py            single-image read-only orchestration
  detectors/             common interface and engine adapters
  models/                manifest parsing and offline integrity registry
  formats/               standard, HEIF, and RAW adapters
  scoring/               triage classification
  workflow/              source, target, operation, validation and routing
  recovery/              TSK metadata recovery, PhotoRec carving, dedup, reports
  calibration/           local corpus discovery, controls, metrics, and reporting
  reports/               CSV, JSON, and future HTML output
tests/                    offline tests
docs/                     architecture and policy
samples/                  policy only; no sensitive fixtures
```

## Recovery roadmap

1. FIS-012 — The Sleuth Kit metadata recovery (implemented; real-host validation pending).
2. FIS-013 — PhotoRec file carving (implemented and locally validated).
3. FIS-014 — recovered-media validation and catalog (implemented).
4. FIS-015 — recovery plus detection pipeline (implemented).
5. FIS-016 — forensic acquisition (system tools required).

The established model licensing, detector evaluation, threshold calibration,
performance, and reporting work continues alongside them.

Licensed under the Apache License 2.0.
