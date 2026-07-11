from src.core.config import get_settings
from src.core.crypto.shamir import combine


class UnsealCoordinator:
    """Collects Shamir shares across requests until the threshold is met, then
    reconstructs the root key. Shares live only in memory."""

    def __init__(self, threshold: int) -> None:
        self._threshold = threshold
        self._shares: dict[int, bytes] = {}

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def provided(self) -> int:
        return len(self._shares)

    def submit(self, share: bytes) -> bytes | None:
        if not share:
            raise ValueError("empty share")
        self._shares[share[0]] = share
        if len(self._shares) >= self._threshold:
            return combine(list(self._shares.values()))
        return None

    def reset(self) -> None:
        self._shares.clear()


# process-wide coordinator
unseal_coordinator = UnsealCoordinator(get_settings().shamir_threshold)
