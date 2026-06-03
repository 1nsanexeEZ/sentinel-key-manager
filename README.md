# Sentinel Key Manager

Secure key management system with ephemeral access control.

## Stack
- Python 3.12
- FastAPI
- PostgreSQL + Redis
- NATS
- UV (Dependency Management)

## How to run
1. Install dependencies: `uv sync`
2. Run docker: `docker-compose up -d`
3. Start app: `uv run uvicorn main:app --reload`