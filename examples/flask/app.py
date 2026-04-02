from flask import Flask, send_from_directory
from open_passkey_flask import create_passkey_blueprint, PasskeyConfig, MemoryChallengeStore, MemoryCredentialStore
import os

app = Flask(__name__)

bp = create_passkey_blueprint(PasskeyConfig(
    rp_id="localhost",
    rp_display_name="Open Passkey Flask Example",
    origin="http://localhost:5001",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
))
app.register_blueprint(bp, url_prefix="/passkey")

SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "shared")
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/passkey.js")
def passkey_js():
    return send_from_directory(SHARED_DIR, "passkey.js")


@app.route("/style.css")
def style_css():
    return send_from_directory(SHARED_DIR, "style.css")


if __name__ == "__main__":
    app.run(port=5001, debug=True)
