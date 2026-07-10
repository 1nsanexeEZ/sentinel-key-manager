class SecretError(Exception):
    """Base class for secret errors."""


class SecretNotFound(SecretError):
    pass
