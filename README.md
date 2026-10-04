# Forensic Image Scanner

Forensic Image Scanner is an early-stage, open source toolkit for local image
content triage across large collections. The intended workflow identifies image
files, hashes original evidence, creates independent normalized representations,
runs local nudity/potential explicit-content models, and emits auditable reports.

> **Experimental:** recursive scanning is not implemented. The Falconsai
> detector supports one explicitly imported local image at a time; its signals
> require human review and must not be treated as legal conclusions.

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

The `models` extra installs Transformers and Safetensors. On Linux, install a
CPU-only PyTorch wheel separately so `pip install -e ".[models]"` never pulls
CUDA components:

```bash
python -m pip install --index-url https://download.pytorch.org/whl/cpu \
  "torch==2.14.1+cpu"
```

NudeNet is blocked because its code licensing is contradictory and the training
provenance of its bundled weights is undocumented. OpenNSFW2 is also deferred
because its GUI OpenCV dependency conflicts with the required headless package.
Review `docs/model_audit.md`, `MODEL_LICENSES.md`, and `MODEL_PROVENANCE.md`
before importing any weights.

## Controlled Falconsai import and offline analysis

Download these files administratively from the audited Falconsai revision,
outside the analysis workflow:

| Artifact | SHA-256 |
| --- | --- |
| `model.safetensors` | `97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830` |
| `config.json` | `cd8c0a19566f199b5c64da402f1d6a9daf80d094fe6536befb060a2cc59449c2` |
| `preprocessor_config.json` | `a34861a24e781942424ad790b82bc99348404a2e64ea882de88c40905851698d` |

Verify every file manually with `sha256sum`, then import it. The command
re-verifies byte size and SHA-256 before copying to a controlled directory:

```bash
forensic-image-scanner model import falconsai-nsfw-image-detection \
  /admin-download/model.safetensors \
  --artifact config.json=/admin-download/config.json \
  --artifact preprocessor_config.json=/admin-download/preprocessor_config.json \
  --model-dir /controlled/models
```

Directory precedence is deterministic: `--model-dir`, then
`FORENSIC_IMAGE_SCANNER_MODEL_DIR`, then the platform data directory. The
import never overwrites an existing model directory.

```bash
forensic-image-scanner model list --model-dir /controlled/models
forensic-image-scanner model verify falconsai-nsfw-image-detection --model-dir /controlled/models
forensic-image-scanner model info falconsai-nsfw-image-detection --model-dir /controlled/models
forensic-image-scanner analyze image.jpg \
  --detector falconsai-nsfw-image-detection \
  --model-dir /controlled/models
```

Use `--json` with `analyze` for structured stdout. The detector uses only
local paths, `local_files_only=True`, a CPU device, Safetensors, and offline
Hugging Face/Transformers environment flags. It classifies only `normal` and
`nsfw`; neither label determines illegality or replaces human review.

## CLI

```bash
forensic-image-scanner --help
forensic-image-scanner scan /path/to/evidence
```

The `scan` command currently validates the path, then clearly reports that mass
scanning is not implemented. It does not process files.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
ruff check .
```

Tests create only synthetic, non-sensitive images and require no network.

## Project layout

```text
src/forensic_image_scanner/
  cli.py                 command-line boundary
  scanner.py             future orchestration layer
  hashing.py             streaming SHA-256
  image_loader.py        standard read-only image loading
  analysis.py            single-image read-only orchestration
  detectors/             common interface and engine adapters
  models/                manifest parsing and offline integrity registry
  formats/               standard, HEIF, and RAW adapters
  scoring/               triage classification
  reports/               CSV, JSON, and future HTML output
tests/                    offline tests
docs/                     architecture and policy
samples/                  policy only; no sensitive fixtures
```

## Roadmap

1. Finalize model/weights licensing and provenance records.
2. Implement recursive discovery with explicit symlink and error policies.
3. Add broader detector evaluation without automatic downloads.
4. Add configurable scoring, reproducibility metadata, and CSV/JSON reports.
5. Add performance, corruption, format, and forensic-invariant tests.
6. Design HTML reporting only after the core audit format is stable.

Licensed under the Apache License 2.0.
