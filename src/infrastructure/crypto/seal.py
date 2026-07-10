class SealedError(Exception):
    """Raised when a root-key-dependent operation runs while sealed."""


class SealState:
    """Holds the root key in memory. Sealed until an operator unseals.

    The root key is never persisted; a restart brings the service back up
    sealed, so a stolen disk cannot decrypt anything on its own.
    """

    def __init__(self) -> None:
        self._root_key: bytes | None = None

    @property
    def sealed(self) -> bool:
        return self._root_key is None

    def unseal(self, root_key: bytes) -> None:
        self._root_key = root_key

    def seal(self) -> None:
        self._root_key = None

    def root_key(self) -> bytes:
        if self._root_key is None:
            raise SealedError("service is sealed")
        return self._root_key


# process-wide seal state
seal_state = SealState()
