"""Passkey configuration with validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .stores import (
    ChallengeStore,
    CredentialStore,
    MemoryChallengeStore,
    MemoryCredentialStore,
)

if TYPE_CHECKING:
    from .session import SessionConfig


@dataclass
class PasskeyConfig:
    rp_id: str
    rp_display_name: str
    origin: str
    challenge_store: ChallengeStore | None = None
    credential_store: CredentialStore | None = None
    challenge_length: int = 32
    challenge_timeout_seconds: float = 300.0
    allow_multiple_credentials: bool = False
    session: SessionConfig | None = None

    def __post_init__(self):
        if not self.rp_id:
            raise ValueError("rp_id is required")
        if not self.origin:
            raise ValueError("origin is required")
        if "://" in self.rp_id or "/" in self.rp_id:
            raise ValueError(f"rp_id must be a bare domain (got {self.rp_id!r})")
        if not self.origin.startswith("https://") and not self.origin.startswith("http://"):
            raise ValueError(f"origin must start with https:// or http:// (got {self.origin!r})")
        if self.challenge_store is None:
            self.challenge_store = MemoryChallengeStore()
        if self.credential_store is None:
            self.credential_store = MemoryCredentialStore()
        if self.session is not None:
            from .session import validate_session_config
            validate_session_config(self.session)
