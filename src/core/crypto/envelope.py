from dataclasses import dataclass

from src.core.crypto import aes


@dataclass(frozen=True)
class WrappedSecret:
    """A secret value encrypted with a per-secret DEK, plus that DEK encrypted
    with the KEK. Neither the plaintext nor the DEK is ever stored in the clear."""

    ciphertext: bytes  # value encrypted under the DEK (nonce||ct)
    encrypted_dek: bytes  # DEK encrypted under the KEK (nonce||ct)


def generate_kek() -> bytes:
    return aes.generate_key()


def wrap_kek(root_key: bytes, kek: bytes) -> bytes:
    """Encrypt a KEK under the root key (for storage)."""
    return aes.encrypt(root_key, kek)


def unwrap_kek(root_key: bytes, encrypted_kek: bytes) -> bytes:
    """Decrypt a stored KEK with the root key."""
    return aes.decrypt(root_key, encrypted_kek)


class EnvelopeCipher:
    """Wraps/unwraps secret values using a single KEK.

    A fresh DEK is generated per value: the value is encrypted with the DEK,
    and the DEK is encrypted with the KEK. Rotating the KEK only requires
    re-encrypting DEKs, not the values themselves.
    """

    def __init__(self, kek: bytes) -> None:
        self._kek = kek

    def wrap(self, plaintext: bytes) -> WrappedSecret:
        dek = aes.generate_key()
        ciphertext = aes.encrypt(dek, plaintext)
        encrypted_dek = aes.encrypt(self._kek, dek)
        return WrappedSecret(ciphertext=ciphertext, encrypted_dek=encrypted_dek)

    def unwrap(self, wrapped: WrappedSecret) -> bytes:
        dek = aes.decrypt(self._kek, wrapped.encrypted_dek)
        return aes.decrypt(dek, wrapped.ciphertext)
