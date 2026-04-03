from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from open_passkey_fastapi import create_passkey_router, PasskeyConfig, MemoryChallengeStore, MemoryCredentialStore
import os

app = FastAPI()

SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "shared")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

router = create_passkey_router(PasskeyConfig(
    rp_id="localhost",
    rp_display_name="Open Passkey FastAPI Example",
    origin="http://localhost:5002",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
))
app.include_router(router, prefix="/passkey")


@app.get("/")
async def index():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


@app.get("/passkey.js")
async def passkey_js():
    return FileResponse(os.path.join(SHARED_DIR, "passkey.js"), media_type="application/javascript")


@app.get("/style.css")
async def style_css():
    return FileResponse(os.path.join(SHARED_DIR, "style.css"), media_type="text/css")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5002, reload=True)
