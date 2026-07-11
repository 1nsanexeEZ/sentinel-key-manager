from datetime import datetime

import asyncpg


class DynamicDbProvider:
    """Creates and drops short-lived LOGIN roles on a target Postgres.

    Requires a privileged DSN (able to CREATE ROLE). Role names are restricted
    to a safe character set and passwords are dollar-quoted, so neither can
    break out of the DDL statement.
    """

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    async def create_login_role(
        self,
        username: str,
        password: str,
        valid_until: datetime,
    ) -> None:
        conn = await asyncpg.connect(self._dsn)
        try:
            await conn.execute(
                f'CREATE ROLE "{username}" LOGIN '
                f"PASSWORD $pw${password}$pw$ "
                f"VALID UNTIL '{valid_until.isoformat()}'"
            )
        finally:
            await conn.close()

    async def drop_role(self, username: str) -> None:
        conn = await asyncpg.connect(self._dsn)
        try:
            await conn.execute(f'DROP ROLE IF EXISTS "{username}"')
        finally:
            await conn.close()
