import uuid

from src.application.secrets.exceptions import SecretNotFound
from src.core.crypto.envelope import WrappedSecret
from src.infrastructure.crypto.keyring import Keyring
from src.infrastructure.repositories.secret_repository import SecretRepository


class SecretService:
    def __init__(self, secrets: SecretRepository, keyring: Keyring) -> None:
        self._secrets = secrets
        self._keyring = keyring

    async def set_secret(
        self,
        path: str,
        value: str,
        actor_id: uuid.UUID | None,
    ) -> None:
        version, cipher = await self._keyring.active_cipher()
        wrapped = cipher.wrap(value.encode())
        await self._secrets.upsert(
            path=path,
            ciphertext=wrapped.ciphertext,
            encrypted_dek=wrapped.encrypted_dek,
            key_version=version,
            created_by=actor_id,
        )

    async def get_secret(self, path: str) -> str:
        secret = await self._secrets.get_by_path(path)
        if secret is None:
            raise SecretNotFound(path)
        cipher = await self._keyring.cipher_for_version(secret.key_version)
        plaintext = cipher.unwrap(
            WrappedSecret(
                ciphertext=secret.ciphertext,
                encrypted_dek=secret.encrypted_dek,
            )
        )
        return plaintext.decode()

    async def list_secrets(self, prefix: str | None = None) -> list[str]:
        return await self._secrets.list_paths(prefix)

    async def delete_secret(self, path: str) -> None:
        if not await self._secrets.delete(path):
            raise SecretNotFound(path)
