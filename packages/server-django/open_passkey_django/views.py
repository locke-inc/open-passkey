"""Django class-based views exposing 4 POST endpoints for WebAuthn ceremonies."""

import json

from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from open_passkey_server import PasskeyConfig, PasskeyError, PasskeyHandler


_handler: PasskeyHandler | None = None


def configure(
    rp_id: str,
    rp_display_name: str,
    origin: str,
    challenge_store,
    credential_store,
    challenge_length: int = 32,
    challenge_timeout_seconds: float = 300.0,
):
    """Must be called before including passkey urls."""
    global _handler
    config = PasskeyConfig(
        rp_id=rp_id,
        rp_display_name=rp_display_name,
        origin=origin,
        challenge_store=challenge_store,
        credential_store=credential_store,
        challenge_length=challenge_length,
        challenge_timeout_seconds=challenge_timeout_seconds,
    )
    _handler = PasskeyHandler(config)


def _handle(fn):
    """Call handler function, catch PasskeyError, return JsonResponse."""
    try:
        return JsonResponse(fn())
    except PasskeyError as e:
        return JsonResponse({"error": str(e)}, status=e.status_code)


@method_decorator(csrf_exempt, name="dispatch")
class BeginRegistrationView(View):
    def post(self, request):
        body = json.loads(request.body)
        return _handle(lambda: _handler.begin_registration(body.get("userId", ""), body.get("username", "")))


@method_decorator(csrf_exempt, name="dispatch")
class FinishRegistrationView(View):
    def post(self, request):
        body = json.loads(request.body)
        return _handle(lambda: _handler.finish_registration(
            body.get("userId", ""),
            body.get("credential", {}),
            body.get("prfSupported", False),
        ))


@method_decorator(csrf_exempt, name="dispatch")
class BeginAuthenticationView(View):
    def post(self, request):
        body = json.loads(request.body) if request.body else {}
        return _handle(lambda: _handler.begin_authentication(body.get("userId", "")))


@method_decorator(csrf_exempt, name="dispatch")
class FinishAuthenticationView(View):
    def post(self, request):
        body = json.loads(request.body)
        return _handle(lambda: _handler.finish_authentication(body.get("userId", ""), body.get("credential", {})))
