from src.application.auth.exceptions import InvalidCredentials, UserAlreadyExists
from src.core.security.password import hash_password, verify_password
from src.core.security.tokens import create_access_token
from src.infrastructure.models.user import User
from src.infrastructure.repositories.user_repository import UserRepository


class AuthService:
    def __init__(self, users: UserRepository) -> None:
        self._users = users

    async def register(self, username: str, password: str) -> User:
        if await self._users.get_by_username(username) is not None:
            raise UserAlreadyExists(username)
        return await self._users.create(username, hash_password(password))

    async def authenticate(self, username: str, password: str) -> str:
        user = await self._users.get_by_username(username)
        if user is None or not user.is_active:
            raise InvalidCredentials()
        if not verify_password(user.password_hash, password):
            raise InvalidCredentials()
        return create_access_token(str(user.id))
