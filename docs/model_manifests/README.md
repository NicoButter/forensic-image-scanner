# Audited reference manifests

These manifests preserve audit conclusions in the same schema used by the
runtime registry. They are documentation, not operational registrations: model
binaries are deliberately absent. To import an approved model, copy its
manifest to `models/<model-id>/manifest.json`, place the exact artifact beside
it, and let `ModelRegistry` verify the bytes.

Blocked reference manifests remain versioned so their status cannot be lost or
silently bypassed.
