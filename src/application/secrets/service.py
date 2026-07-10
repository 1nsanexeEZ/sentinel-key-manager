import uuid

from src.application.secrets.exceptions import SecretNotFound
from src.core.crypto.envelope import WrappedSecret
from src.infrastructure.crypto.keyring import Keyring
from src.infrastructure.models.secret import Secret
from src.infrastructure.models.secret_version import SecretVersion
from src.infrastructure.repositories.secret_repository import SecretRepository
from src.infrastructure.repositories.secret_version_repository import (
    SecretVersionRepository,
)


class SecretService:
    def __init__(
        self,
        secrets: SecretRepository,
        versions: SecretVersionRepository,
        keyring: Keyring,
    ) -> None:
        self._secrets = secrets
        self._versions = versions
        self._keyring = keyring

    async def set_secret(
        self,
        path: str,
        value: str,
        actor_id: uuid.UUID | None,
    ) -> int:
        version, cipher = await self._keyring.active_cipher()
        wrapped = cipher.wrap(value.encode())
        secret = await self._secrets.upsert(
            path=path,
            ciphertext=wrapped.ciphertext,
            encrypted_dek=wrapped.encrypted_dek,
            key_version=version,
            created_by=actor_id,
        )
        return await self._append_version(secret, wrapped, version)

    async def get_secret(self, path: str, version: int | None = None) -> str:
        secret = await self._secrets.get_by_path(path)
        if secret is None:
            raise SecretNotFound(path)
        if version is None:
            return await self._decrypt(secret.ciphertext, secret.encrypted_dek, secret.key_version)
        snapshot = await self._versions.get(secret.id, version)
        if snapshot is None:
            raise SecretNotFound(f"{path}@{version}")
        return await self._decrypt(
            snapshot.ciphertext, snapshot.encrypted_dek, snapshot.key_version
        )

    async def rollback(self, path: str, to_version: int) -> str:
        secret = await self._secrets.get_by_path(path)
        if secret is None:
            raise SecretNotFound(path)
        snapshot = await self._versions.get(secret.id, to_version)
        if snapshot is None:
            raise SecretNotFound(f"{path}@{to_version}")
        secret = await self._secrets.upsert(
            path=path,
            ciphertext=snapshot.ciphertext,
            encrypted_dek=snapshot.encrypted_dek,
            key_version=snapshot.key_version,
            created_by=secret.created_by,
        )
        await self._append_version(secret, snapshot, snapshot.key_version)
        return await self._decrypt(
            snapshot.ciphertext, snapshot.encrypted_dek, snapshot.key_version
        )

    async def list_secrets(self, prefix: str | None = None) -> list[str]:
        return await self._secrets.list_paths(prefix)

    async def list_versions(self, path: str) -> list[int]:
        secret = await self._secrets.get_by_path(path)
        if secret is None:
            raise SecretNotFound(path)
        return await self._versions.list_versions(secret.id)

    async def delete_secret(self, path: str) -> None:
        if not await self._secrets.delete(path):
            raise SecretNotFound(path)

    async def _append_version(
        self,
        secret: Secret,
        payload: WrappedSecret | SecretVersion,
        key_version: int,
    ) -> int:
        vnum = await self._versions.next_version(secret.id)
        await self._versions.add(
            secret_id=secret.id,
            version=vnum,
            ciphertext=payload.ciphertext,
            encrypted_dek=payload.encrypted_dek,
            key_version=key_version,
        )
        return vnum

    async def _decrypt(
        self,
        ciphertext: bytes,
        encrypted_dek: bytes,
        key_version: int,
    ) -> str:
        cipher = await self._keyring.cipher_for_version(key_version)
        plaintext = cipher.unwrap(
            WrappedSecret(ciphertext=ciphertext, encrypted_dek=encrypted_dek)
        )
        return plaintext.decode()
