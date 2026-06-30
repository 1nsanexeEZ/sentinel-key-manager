from fastapi import FastAPI

from src.core.config import get_settings

settings = get_settings()

app = FastAPI(title=settings.app_name, debug=settings.debug)


@app.get("/health")
def health():
    return {"status": "healthy"}
