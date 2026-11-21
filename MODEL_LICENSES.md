# Model licenses

The Forensic Image Scanner core and project-written IPC bridge are Apache-2.0.
The optional NudeNet distribution remains governed by the license shipped
upstream and is installed separately by the operator.

## NudeNet 320n and 640m

- NudeNet 3.4.2 ships the GNU AGPL-3.0 license in its wheel. PyPI metadata lists
  MIT. The project records and handles NudeNet as AGPL-3.0 based on the
  distributed license and the upstream repository.
- Both ONNX artifacts declare AGPL-3.0 in their exporter metadata. A separate
  NudeNet weights grant and verifiable training-data license remain unconfirmed.
- Both variants are optional, experimental, and have partial training
  provenance. The application records artifact integrity independently.
- The repository and core distribution carry neither the upstream wheel nor
  the model weights. The opt-in installer fetches the pinned upstream files
  for local use without changing their terms. Installation approval records a
  software choice and acknowledges the displayed upstream license notice.

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
- Installation verification does not alter this status: SHA-256 identity is not
  evidence about the proprietary training dataset or its license.

See `docs/model_audit.md` for evidence, hashes, and limitations.
