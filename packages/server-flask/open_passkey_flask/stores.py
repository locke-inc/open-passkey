"""Challenge and credential store interfaces with in-memory implementations."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from threading import Lock
from time import time


class PasskeyError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class StoredCredential:
    credential_id: bytes
    public_key_cose: bytes
    sign_count: int
    user_id: str
    prf_salt: bytes | None = None
    prf_supported: bool = False


class ChallengeStore(ABC):
    """Manages single-use, time-limited WebAuthn challenges. Must be thread-safe."""

    @abstractmethod
    def store(self, key: str, challenge: str, timeout_seconds: float) -> None: ...

    @abstractmethod
    def consume(self, key: str) -> str:
        """Retrieve and delete a challenge. Raises PasskeyError if not found/expired."""
        ...


class CredentialStore(ABC):
    """Manages WebAuthn credential persistence. Must be thread-safe."""

    @abstractmethod
    def store(self, cred: StoredCredential) -> None: ...

    @abstractmethod
    def get(self, credential_id: bytes) -> StoredCredential: ...

    @abstractmethod
    def get_by_user(self, user_id: str) -> list[StoredCredential]: ...

    @abstractmethod
    def update(self, cred: StoredCredential) -> None: ...

    @abstractmethod
    def delete(self, credential_id: bytes) -> None: ...


# --- In-memory implementations ---

_CLEANUP_INTERVAL = 100


@dataclass
class _ChallengeEntry:
    challenge: str
    expires_at: float


class MemoryChallengeStore(ChallengeStore):
    def __init__(self):
        self._lock = Lock()
        self._entries: dict[str, _ChallengeEntry] = {}
        self._write_count = 0

    def store(self, key: str, challenge: str, timeout_seconds: float) -> None:
        with self._lock:
            self._entries[key] = _ChallengeEntry(challenge, time() + timeout_seconds)
            self._write_count += 1
            if self._write_count >= _CLEANUP_INTERVAL:
                self._write_count = 0
                now = time()
                self._entries = {
                    k: v for k, v in self._entries.items() if v.expires_at > now
                }

    def consume(self, key: str) -> str:
        with self._lock:
            entry = self._entries.pop(key, None)
            if entry is None or time() > entry.expires_at:
                raise PasskeyError("challenge not found or expired")
            return entry.challenge


class MemoryCredentialStore(CredentialStore):
    def __init__(self):
        self._lock = Lock()
        self._creds: list[StoredCredential] = []

    def store(self, cred: StoredCredential) -> None:
        with self._lock:
            self._creds.append(cred)

    def get(self, credential_id: bytes) -> StoredCredential:
        with self._lock:
            for c in self._creds:
                if c.credential_id == credential_id:
                    return c
        raise PasskeyError("credential not found")

    def get_by_user(self, user_id: str) -> list[StoredCredential]:
        with self._lock:
            return [c for c in self._creds if c.user_id == user_id]

    def update(self, cred: StoredCredential) -> None:
        with self._lock:
            for i, c in enumerate(self._creds):
                if c.credential_id == cred.credential_id:
                    self._creds[i] = cred
                    return
        raise PasskeyError("credential not found")

    def delete(self, credential_id: bytes) -> None:
        with self._lock:
            for i, c in enumerate(self._creds):
                if c.credential_id == credential_id:
                    self._creds.pop(i)
                    return
        raise PasskeyError("credential not found")
