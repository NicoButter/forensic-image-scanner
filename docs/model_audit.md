# Formal model audit

Audit date: 2026-10-03. No inference was run on evidence or test images. URLs
and revisions below are immutable where the hosting service supports it.

## Decision

**The first officially implemented detector is the Falconsai global classifier,
with `provenance_status: partial`.** It accepts only a registry-verified local
model and never downloads or installs weights automatically.

NudeNet 320n is `MODEL_STATUS = BLOCKED_PROVENANCE`. The registry must reject
it even when its bytes match the recorded hash.

## Comparison

| Item | NudeNet 3.4.2 / 320n | Falconsai/nsfw_image_detection |
| --- | --- | --- |
| Function | 18-class body-part object detector | 2-class global image classifier |
| Source revision | NudeNet commit `6ccc81c6c305cccfd46d92b414f8a5c0a816574d` | HF revision `96cb0d0342c7afb80cab76ecc58b265fa44da256` |
| Software license | Contradictory: PyPI metadata says MIT; wheel/repository LICENSE is AGPL-3.0 | Transformers Apache-2.0; PyTorch BSD-style; Safetensors Apache-2.0 |
| Weights license | ONNX metadata says AGPL-3.0/Ultralytics; no separate NudeNet weights grant was found | Repository model-card metadata declares Apache-2.0; no standalone LICENSE file was found |
| Training data | No verifiable dataset/training documentation found for 320n | Proprietary dataset, approximately 80,000 images; only `normal`/`nsfw` summary is public |
| Primary artifact | `320n.onnx`, 12,150,158 bytes | `model.safetensors`, 343,223,968 bytes |
| SHA-256 | `c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f` | `97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830` |
| Framework | YOLOv8n export; ONNX Runtime; Ultralytics exporter 8.2.46 | ViTForImageClassification; PyTorch/Transformers; Safetensors |
| Input | RGB-like tensor; exported dynamic shape; adapter uses 320×320 | RGB, 224×224, ViT patches 16×16 |
| Python 3.14 | Package installed and ONNX session opened locally; licensing blocks use | Current Torch, Transformers, and Safetensors publish Python 3.14-compatible distributions |
| Fully offline | Technically yes because the wheel bundles a weight, but implicit resolution is prohibited | Yes after manual import of weights/configuration and use of local-only loader settings |
| Apache-2.0 project fit | No safe integration decision: AGPL code plus ambiguous metadata and undocumented training provenance | Code and declared weights license are compatible; dataset opacity keeps status `partial` |
| Registry status | `blocked_provenance` | `partial` |

## NudeNet 3.4.2 findings

### Wheel contents and revision

The PyPI wheel `nudenet-3.4.2-py3-none-any.whl` has SHA-256
`5937dbd84e5d8e5de038f08ffea5a1bb50a08475776bf2b4795914ce0eaf0331`
and was uploaded at 2024-07-03 17:32:02 UTC. It contains only the package code,
console entry point, two identical license files, and the bundled model:

- `nudenet/nudenet.py`;
- `nudenet/320n.onnx`;
- `nudenet-3.4.2.dist-info/LICENSE` and `LICENSE.md`;
- packaging metadata and entry-point records.

The installed `nudenet.py`, LICENSE, and `320n.onnx` match the files at commit
`6ccc81c6c305cccfd46d92b414f8a5c0a816574d` byte-for-byte. That commit was
authored at 2024-07-03 17:31:17 UTC, 45 seconds before the wheel upload, and its
`setup.py` declares version 3.4.2. No signed source tag identifying 3.4.2 was
found, so the immutable commit is the reproducible revision.

The wheel includes `320n.onnx`; it is not downloaded at runtime. The same bytes
are stored both in the audited commit and GitHub release `v3.4-weights`:

```text
size:   12,150,158 bytes
sha256: c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f
```

### MIT/AGPL discrepancy

PyPI `METADATA`, `setup.py`, and the Trove classifier say MIT. However, both
license documents actually shipped inside that wheel contain the complete GNU
Affero General Public License v3.0, identical to the repository license at the
matching commit. The repository is currently also classified as AGPL-3.0.

The actual distributed license files are therefore inconsistent with the
package metadata. The project must not treat the PyPI `License: MIT` string as
a reliable grant. Incorporating the package into an Apache-2.0 distribution is
blocked pending explicit clarification from the copyright holder.

### Weights and training provenance

The ONNX artifact contains exporter metadata naming Ultralytics, YOLOv8,
exporter version 8.2.46, export date 2024-06-29, task `detect`, 320×320 input,
18 class names, and `license: AGPL-3.0 License (https://ultralytics.com/license)`.
This is evidence of the exporter/model metadata, but no separate license grant
from NudeNet for the trained weights was found. It is not safe to infer that the
PyPI MIT field covers the weight.

The audited repository tree contains no training script, dataset manifest,
dataset license, datasheet, collection method, or reproducible training record
for 320n. The only verifiable description is that it is based on YOLOv8n.
Consequently both the training-data origin and the authority to redistribute
the trained artifact remain insufficiently documented.

Known limitations include class-specific detection rather than global context,
threshold and NMS sensitivity, demographic/domain bias that cannot be measured
without the training corpus, false positives/negatives, no legal/contextual
reasoning, and an implicit default-model constructor that violates this
project's explicit-registry policy.

## Falconsai/nsfw_image_detection findings

The audited immutable repository revision is
`96cb0d0342c7afb80cab76ecc58b265fa44da256`. Its model-card metadata declares
`apache-2.0`. The repository has no standalone license document, so the exact
recorded basis for the weights license is that model-card declaration.

The primary artifact is:

```text
filename: model.safetensors
size:     343,223,968 bytes
sha256:   97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830
```

Hugging Face publishes the same SHA-256 and size in its LFS metadata. The model
is an 85.8-million-parameter, float32 Vision Transformer using
`ViTForImageClassification`: 224×224 RGB input, 16×16 patches, 12 layers, 12
 attention heads, 768 hidden dimensions, and two labels: `normal` and `nsfw`.

The local Transformers reconstruction additionally requires two audited JSON
artifacts. The controlled manifest verifies them before loading:

| Artifact | Bytes | SHA-256 | Purpose |
| --- | ---: | --- | --- |
| `config.json` | 724 | `cd8c0a19566f199b5c64da402f1d6a9daf80d094fe6536befb060a2cc59449c2` | ViT architecture and labels |
| `preprocessor_config.json` | 325 | `a34861a24e781942424ad790b82bc99348404a2e64ea882de88c40905851698d` | RGB resize/rescale/normalization |

The model card says fine-tuning used a proprietary dataset of approximately
80,000 images divided into those two classes. It does not publish the dataset,
a dataset license, collection sources, consent details, sampling methodology,
or a reproducible split. The Apache-2.0 declaration for the model must not be
misrepresented as a license or provenance statement for that dataset. This is
why the status is `partial`, not `verified`.

Current Python 3.14 wheels exist for PyTorch, and current Transformers and
Safetensors releases declare Python 3.14 support. After an administrator
downloads the pinned revision once, records hashes, and moves the required
files into the controlled model directory, Transformers can operate on local
paths with offline/local-only settings. The future adapter must set offline
mode and `local_files_only=True`; it must never pass the Hub model ID at
analysis time.

Known limitations include binary labels that collapse many contexts, unknown
composition and representativeness of proprietary data, possible demographic
and cultural bias, dataset shift, adversarial/evasive content, false positives
and negatives, lack of localization, and no legal or contextual judgment.

## Controlled import policy

```text
administrator downloads immutable revision outside analysis
    -> verifies every published SHA-256
    -> stores files under models/<model-id>/
    -> creates schema-v1 manifest.json
    -> ModelRegistry validates policy, existence, size, and SHA-256
    -> detector receives VerifiedModel
    -> offline inference (future milestone)
```

The registry contains no HTTP client and never invokes a framework's Hub
resolver. Blocked models are rejected before their artifact is opened.
