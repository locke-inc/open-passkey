"""Error classes with code field matching spec/vectors/ error strings."""


class WebAuthnError(Exception):
    def __init__(self, code: str, message: str | None = None):
        self.code = code
        super().__init__(message or code)


class TypeMismatchError(WebAuthnError):
    def __init__(self):
        super().__init__("type_mismatch")


class ChallengeMismatchError(WebAuthnError):
    def __init__(self):
        super().__init__("challenge_mismatch")


class OriginMismatchError(WebAuthnError):
    def __init__(self):
        super().__init__("origin_mismatch")


class RPIDMismatchError(WebAuthnError):
    def __init__(self):
        super().__init__("rp_id_mismatch")


class SignatureInvalidError(WebAuthnError):
    def __init__(self):
        super().__init__("signature_invalid")


class UnsupportedAlgorithmError(WebAuthnError):
    def __init__(self, message: str | None = None):
        super().__init__("unsupported_cose_algorithm", message)


class SignCountRollbackError(WebAuthnError):
    def __init__(self):
        super().__init__("sign_count_rollback")


class UserPresenceRequiredError(WebAuthnError):
    def __init__(self):
        super().__init__("user_presence_required")


class UserVerificationRequiredError(WebAuthnError):
    def __init__(self):
        super().__init__("user_verification_required")


class UnsupportedAttestationFormatError(WebAuthnError):
    def __init__(self, fmt: str = ""):
        super().__init__("unsupported_attestation_format", f"unsupported attestation format: {fmt}")


class TokenBindingUnsupportedError(WebAuthnError):
    def __init__(self):
        super().__init__("token_binding_unsupported")


class InvalidBackupStateError(WebAuthnError):
    def __init__(self):
        super().__init__("invalid_backup_state")


class InvalidAttestationStatementError(WebAuthnError):
    def __init__(self, message: str | None = None):
        super().__init__("invalid_attestation_statement", message)
