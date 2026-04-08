from django.urls import include, path
from django.http import FileResponse
import os

from open_passkey_django.views import configure
from open_passkey_server import MemoryChallengeStore, MemoryCredentialStore
from open_passkey_server.session import SessionConfig

configure(
    rp_id="localhost",
    rp_display_name="Open Passkey Django Example",
    origin="http://localhost:5003",
    challenge_store=MemoryChallengeStore(),
    credential_store=MemoryCredentialStore(),
    session=SessionConfig(
        secret="django-example-secret-must-be-32-chars",
        secure=False,
    ),
)

STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
SHARED_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "shared")


def index(request):
    return FileResponse(open(os.path.join(STATIC_DIR, "index.html"), "rb"), content_type="text/html")


def passkey_js(request):
    return FileResponse(open(os.path.join(SHARED_DIR, "passkey.js"), "rb"), content_type="application/javascript")


def style_css(request):
    return FileResponse(open(os.path.join(SHARED_DIR, "style.css"), "rb"), content_type="text/css")


urlpatterns = [
    path("", index),
    path("passkey.js", passkey_js),
    path("style.css", style_css),
    path("passkey/", include("open_passkey_django.urls")),
]
