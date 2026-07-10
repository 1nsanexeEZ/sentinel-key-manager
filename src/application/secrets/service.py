import uuid

from src.application.secrets.exceptions import SecretNotFound
from src.infrastructure.models.secret import Secret
from src.infrastructure.repositories.secret_repository import SecretRepository


class SecretService:
    def __init__(self, secrets: SecretRepository) -> None:
        self._secrets = secrets

    async def set_secret(
        self,
        path: str,
        value: str,
        actor_id: uuid.UUID | None,
    ) -> Secret:
        return await self._secrets.upsert(path, value, actor_id)

    async def get_secret(self, path: str) -> Secret:
        secret = await self._secrets.get_by_path(path)
        if secret is None:
            raise SecretNotFound(path)
        return secret

    async def list_secrets(self, prefix: str | None = None) -> list[str]:
        return await self._secrets.list_paths(prefix)

    async def delete_secret(self, path: str) -> None:
        if not await self._secrets.delete(path):
            raise SecretNotFound(path)
