# Model provenance

Audit date: 2026-10-03. These records do not enable inference.

## nudenet-320n

- Package: PyPI `nudenet==3.4.2`.
- Wheel SHA-256: `5937dbd84e5d8e5de038f08ffea5a1bb50a08475776bf2b4795914ce0eaf0331`.
- Source revision: `6ccc81c6c305cccfd46d92b414f8a5c0a816574d`.
- Source: `https://github.com/notAI-tech/NudeNet`.
- Release: `v3.4-weights`.
- Artifact: `320n.onnx`, 12,150,158 bytes.
- Artifact SHA-256: `c15d8273adad2d0a92f014cc69ab2d6c311a06777a55545f2c4eb46f51911f0f`.
- Framework: YOLOv8n exported to ONNX; ONNX Runtime.
- Export metadata: Ultralytics 8.2.46, 2024-06-29, 320×320, 18 labels.
- Dataset/training: not documented reproducibly in the audited source tree.
- Status: `blocked_provenance`.

The wheel, commit, and release asset contain identical model bytes. This proves
artifact identity, not the origin or licensing of the training data.

## falconsai-nsfw-image-detection

- Publisher: Falconsai on Hugging Face.
- Source: `https://huggingface.co/Falconsai/nsfw_image_detection`.
- Audited revision: `96cb0d0342c7afb80cab76ecc58b265fa44da256`.
- Artifact: `model.safetensors`, 343,223,968 bytes.
- Artifact SHA-256: `97b2ce64ec146884b37f98ee7944ca4891aa72f6827dc0cb10684a1cbecd5830`.
- Required configuration artifact: `config.json`, 724 bytes,
  SHA-256 `cd8c0a19566f199b5c64da402f1d6a9daf80d094fe6536befb060a2cc59449c2`.
- Required preprocessing artifact: `preprocessor_config.json`, 325 bytes,
  SHA-256 `a34861a24e781942424ad790b82bc99348404a2e64ea882de88c40905851698d`.
- Framework: PyTorch, Transformers, Safetensors; ViT image classifier.
- Architecture: 85.8M float32 parameters, 224×224 RGB, patch size 16,
  12 layers, 12 heads, hidden size 768.
- Labels: `normal`, `nsfw`.
- Dataset/training: model card states a proprietary dataset of approximately
  80,000 images divided into `normal` and `nsfw`; no dataset artifact, license,
  or detailed collection provenance is published.
- Status: `partial`; selected as the first future detector candidate.

Before inference, manually import all three pinned files; the command creates
`manifest.json` and the registry verifies each. Never use an unpinned Hub ID at
runtime.
