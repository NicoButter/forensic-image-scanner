# Forensic principles

## Original evidence is read-only

Original files are inputs only. The tool must never modify, rename, move, or
convert them, and must not alter their timestamps or metadata. SHA-256 is
calculated over the original byte stream before any normalization.

## Independent normalization

Orientation correction and RGB conversion happen on an independent in-memory
representation. If controlled temporary storage is introduced later, it must
be outside the evidence tree, have an explicit lifecycle, and never replace an
original.

## Reproducibility and auditability

Results record the detector, detector version, model identity, model version,
SHA-256 of the model weights, analysis time, observations, scores, and errors.
Configuration and scoring thresholds must be reportable. Model artifacts must
be verified against recorded hashes.

## Human review is mandatory

Models produce fallible indicators for content triage and prioritization. They
do not make legal conclusions, do not establish intent or context, and do not
determine whether a file constitutes illegal material. LOW, REVIEW, and HIGH
are workflow priorities only. A qualified human must review relevant results.

## Local processing and data minimization

Image bytes, hashes, metadata, and results must not be sent to cloud APIs or
external services. Runtime telemetry is prohibited. Operators remain
responsible for access controls, secure storage, retention, and applicable law.
