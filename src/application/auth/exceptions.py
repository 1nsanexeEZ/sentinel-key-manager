class AuthError(Exception):
    """Base class for authentication errors."""


class UserAlreadyExists(AuthError):
    pass


class InvalidCredentials(AuthError):
    pass
