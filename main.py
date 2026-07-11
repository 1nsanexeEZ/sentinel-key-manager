from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import get_settings
from src.presentation.security import SecurityHeadersMiddleware
from src.infrastructure.crypto.keyring import KeyringError, load_root_key
from src.infrastructure.crypto.seal import seal_state
from src.infrastructure.database import get_session
from src.presentation.auth.router import router as auth_router
from src.presentation.secrets.router import router as secrets_router
from src.presentation.sys.router import router as sys_router

settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(secrets_router)
app.include_router(sys_router)


@app.on_event("startup")
def _auto_unseal() -> None:
    # opt-in dev convenience; production stays sealed until an operator unseals
    if settings.auto_unseal and settings.master_key:
        try:
            seal_state.unseal(load_root_key())
        except KeyringError:
            pass


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/health/db")
async def health_db(session: AsyncSession = Depends(get_session)):
    await session.execute(text("SELECT 1"))
    return {"status": "healthy", "database": "up"}
