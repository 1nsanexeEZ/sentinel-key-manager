from fastapi import Depends, FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.infrastructure.database import get_session
from src.presentation.auth.router import router as auth_router
from src.presentation.secrets.router import router as secrets_router

settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug)

app.include_router(auth_router)
app.include_router(secrets_router)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/health/db")
async def health_db(session: AsyncSession = Depends(get_session)):
    await session.execute(text("SELECT 1"))
    return {"status": "healthy", "database": "up"}
