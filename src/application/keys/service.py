from src.core.crypto.envelope import generate_kek, wrap_kek
from src.infrastructure.repositories.key_repository import KeyRepository


class KeyRotationService:
    """Rotates the KEK. New writes use the new active version; existing secrets
    keep their old key_version and stay readable, so rotation has no downtime."""

    def __init__(self, keys: KeyRepository, root_key: bytes) -> None:
        self._keys = keys
        self._root_key = root_key

    async def rotate(self) -> int:
        new_version = await self._keys.max_version() + 1
        kek = generate_kek()
        encrypted = wrap_kek(self._root_key, kek)
        await self._keys.add(
            version=new_version,
            encrypted_kek=encrypted,
            is_active=False,
        )
        await self._keys.set_active_version(new_version)
        return new_version
