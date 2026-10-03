# Contributing

Contributions should preserve the local-only and read-only evidence boundaries.
Before opening a change:

1. Create a virtual environment and install `.[dev]`.
2. Run `pytest` and `ruff check .`.
3. Add offline tests for behavior changes.
4. Document the license, provenance, maintenance status, and supported Python
   versions of every proposed dependency.
5. Never add sensitive images, explicit fixtures, real evidence, model weights,
   telemetry, or automatic runtime downloads.

Detector changes must implement the common `Detector` interface. Keep scoring
and reporting independent from engine-specific output formats.
