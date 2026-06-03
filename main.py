from fastapi import FastAPI

app = FastAPI(title="Sentinel Key Manager API")

@app.get("/health")
def health():
    return {"status": "healthy"}