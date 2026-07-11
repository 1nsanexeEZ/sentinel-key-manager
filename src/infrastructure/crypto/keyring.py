import base64

from src.core.config import get_settings
from src.core.crypto.envelope import (
    EnvelopeCipher,
    generate_kek,
    unwrap_kek,
    wrap_kek,
)
from src.infrastructure.repositories.key_repository import KeyRepository


class KeyringError(Exception):
    pass


def decode_root_key(raw: str) -> bytes:
    if not raw:
        raise KeyringError("root key is empty")
    try:
        key = base64.b64decode(raw)
    except (ValueError, TypeError) as exc:
        raise KeyringError("root key is not valid base64") from exc
    if len(key) != 32:
        raise KeyringError("root key must decode to 32 bytes")
    return key


def load_root_key() -> bytes:
    return decode_root_key(get_settings().master_key)


class Keyring:
    """Manages KEKs on top of a root key.

    KEKs are stored encrypted under the root key; this class decrypts them in
    memory to hand out an EnvelopeCipher for the active (or a specific) version.
    """

    def __init__(self, keys: KeyRepository, root_key: bytes) -> None:
        self._keys = keys
        self._root_key = root_key

    async def active_cipher(self) -> tuple[int, EnvelopeCipher]:
        record = await self._keys.get_active()
        if record is None:
            record = await self._bootstrap()
        kek = unwrap_kek(self._root_key, record.encrypted_kek)
        return record.version, EnvelopeCipher(kek)

    async def cipher_for_version(self, version: int) -> EnvelopeCipher:
        record = await self._keys.get_by_version(version)
        if record is None:
            raise KeyringError(f"unknown key version {version}")
        kek = unwrap_kek(self._root_key, record.encrypted_kek)
        return EnvelopeCipher(kek)

    async def _bootstrap(self):
        kek = generate_kek()
        encrypted = wrap_kek(self._root_key, kek)
        return await self._keys.add(version=1, encrypted_kek=encrypted, is_active=True)
