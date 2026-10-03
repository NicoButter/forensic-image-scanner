# Controlled model directory

Model binaries and operational manifests live here but are not committed. The
only versioned files in this directory are this policy and the manifest example.

Expected layout:

```text
models/
└── <model-id>/
    ├── manifest.json
    └── model.onnx | model.safetensors
```

Import is an explicit administrative operation:

```text
manual download/import -> verify published SHA-256 -> place artifact in the
controlled directory -> create manifest.json -> registry verification ->
offline inference
```

The application does not download models. Keep the analysis environment
network-disconnected and use immutable source revisions when importing.
