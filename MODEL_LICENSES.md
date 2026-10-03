# Model licenses

Audit date: 2026-10-03. Only the explicit, local Falconsai single-image path is
implemented; it remains experimental and requires human review.

## NudeNet 320n

- Code/package: **blocked ambiguity**. PyPI metadata and `setup.py` say MIT,
  while both license files shipped in wheel 3.4.2 are AGPL-3.0 and match the
  repository at the corresponding commit.
- Weights: the ONNX metadata says `AGPL-3.0 License` and identifies Ultralytics,
  but no separate NudeNet grant for the trained weight was found.
- Training dataset: no license or verifiable provenance found.
- Redistribution: prohibited by project policy pending written clarification
  of the code/weights licensing and training provenance.
- Status: `blocked_provenance`.

The PyPI `License: MIT` string must not be extended by assumption to the files
whose actual bundled license and origin are in dispute.

## Falconsai/nsfw_image_detection

- Repository/model-card declaration: Apache-2.0.
- Standalone weights license file: none found in the audited revision.
- Recorded weights basis: the repository-level Apache-2.0 model-card metadata.
- Runtime code: Transformers and Safetensors are Apache-2.0; PyTorch uses its
  BSD-style license. These are compatible with this Apache-2.0 project.
- Training dataset: proprietary and not released; the model license must not be
  treated as a dataset license.
- Redistribution: appears permitted under the declared Apache-2.0 terms with
  required notices, but legal review remains appropriate before redistributing
  the 343 MB artifact rather than requiring users to import it themselves.
- Status: `partial`.

See `docs/model_audit.md` for evidence, hashes, and limitations.
