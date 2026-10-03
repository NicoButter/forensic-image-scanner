# Security policy

This project is pre-alpha and has no supported production release yet. Please
report suspected vulnerabilities privately to the repository owner rather than
opening a public issue. Include affected versions, reproduction steps, impact,
and any suggested mitigation; do not attach sensitive or evidentiary images.

The tool does not replace evidence-handling procedures. Run it in an appropriately
isolated environment with least privilege and read-only mounts where available.
Dependency installation may access package indexes, but runtime analysis must not
send images, hashes, metadata, or results to external services.
