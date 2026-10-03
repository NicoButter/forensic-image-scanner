"""Model registry exceptions."""


class ModelRegistryError(RuntimeError):
    """Base class for deterministic model loading failures."""


class InvalidManifestError(ModelRegistryError):
    """Raised when a manifest is malformed or uses an unsupported schema."""


class ModelNotFoundError(ModelRegistryError):
    """Raised when a manifest or its model artifact does not exist."""


class ModelBlockedError(ModelRegistryError):
    """Raised when policy explicitly blocks a model."""


class ModelIntegrityError(ModelRegistryError):
    """Raised when an artifact differs from its manifest."""


class ModelNotInstalledError(ModelNotFoundError):
    """Raised when a requested model has no controlled registration."""


class ModelArtifactMissingError(ModelNotFoundError):
    """Raised when a registered artifact is missing."""


class ModelHashMismatchError(ModelIntegrityError):
    """Raised when an artifact's SHA-256 differs from its manifest."""


class ModelAlreadyInstalledError(ModelRegistryError):
    """Raised when an import would overwrite an existing model directory."""
