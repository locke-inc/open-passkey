"""Pydantic request/response models for the passkey endpoints."""

from pydantic import BaseModel


class BeginRegistrationRequest(BaseModel):
    userId: str
    username: str


class CredentialResponse(BaseModel):
    clientDataJSON: str
    attestationObject: str


class FinishRegistrationCredential(BaseModel):
    id: str
    rawId: str
    type: str
    response: CredentialResponse


class FinishRegistrationRequest(BaseModel):
    userId: str
    credential: FinishRegistrationCredential
    prfSupported: bool | None = None


class BeginAuthenticationRequest(BaseModel):
    userId: str | None = None


class AuthenticationResponse(BaseModel):
    clientDataJSON: str
    authenticatorData: str
    signature: str
    userHandle: str | None = None


class FinishAuthenticationCredential(BaseModel):
    id: str
    rawId: str
    type: str
    response: AuthenticationResponse


class FinishAuthenticationRequest(BaseModel):
    userId: str
    credential: FinishAuthenticationCredential
