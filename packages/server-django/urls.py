"""URL configuration for open-passkey Django views.

Usage in your project's urls.py:

    from server_django.views import configure
    from server_django.stores import MemoryChallengeStore, MemoryCredentialStore

    configure(
        rp_id="example.com",
        rp_display_name="Example",
        origin="https://example.com",
        challenge_store=MemoryChallengeStore(),
        credential_store=MemoryCredentialStore(),
    )

    urlpatterns = [
        path("passkey/", include("server_django.urls")),
    ]
"""

from django.urls import path

from .views import (
    BeginAuthenticationView,
    BeginRegistrationView,
    FinishAuthenticationView,
    FinishRegistrationView,
)

urlpatterns = [
    path("register/begin", BeginRegistrationView.as_view(), name="passkey-register-begin"),
    path("register/finish", FinishRegistrationView.as_view(), name="passkey-register-finish"),
    path("login/begin", BeginAuthenticationView.as_view(), name="passkey-login-begin"),
    path("login/finish", FinishAuthenticationView.as_view(), name="passkey-login-finish"),
]
