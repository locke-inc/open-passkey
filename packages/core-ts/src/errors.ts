// Error codes match the "error" field in spec/vectors/ JSON.
export class WebAuthnError extends Error {
  constructor(
    public readonly code: string,
    message?: string,
  ) {
    super(message ?? code);
    this.name = "WebAuthnError";
  }
}

export class TypeMismatchError extends WebAuthnError {
  constructor() {
    super("type_mismatch");
  }
}

export class ChallengeMismatchError extends WebAuthnError {
  constructor() {
    super("challenge_mismatch");
  }
}

export class OriginMismatchError extends WebAuthnError {
  constructor() {
    super("origin_mismatch");
  }
}

export class RPIDMismatchError extends WebAuthnError {
  constructor() {
    super("rp_id_mismatch");
  }
}

export class SignatureInvalidError extends WebAuthnError {
  constructor() {
    super("signature_invalid");
  }
}

export class UnsupportedAlgorithmError extends WebAuthnError {
  constructor(message?: string) {
    super("unsupported_cose_algorithm", message);
  }
}

export class SignCountRollbackError extends WebAuthnError {
  constructor() {
    super("sign_count_rollback");
  }
}
