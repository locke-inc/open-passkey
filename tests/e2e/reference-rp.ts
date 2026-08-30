import { createHash } from "node:crypto";
import {
  verifyAuthentication,
  verifyRegistration,
} from "@open-passkey/core";

type UserVerification = "required" | "preferred" | "discouraged";
type Mediation = "optional" | "conditional";

interface CredentialResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle: string | null;
}

interface RegistrationResponse {
  clientDataJSON: string;
  attestationObject: string;
}

interface CredentialRecord {
  credentialId: string;
  userId: string;
  userName: string;
  publicKeyCose: Uint8Array;
  signCount: number;
}

interface PendingRegistration {
  kind: "registration";
  challenge: Uint8Array;
  userId: string;
  userName: string;
  expiresAt: number;
  consumed: boolean;
}

interface PendingAuthentication {
  kind: "authentication";
  challenge: Uint8Array;
  expectedUserId?: string;
  candidates: CredentialRecord[];
  userVerification: UserVerification;
  mediation: Mediation;
  expiresAt: number;
  signal?: AbortSignal;
  consumed: boolean;
}

type PendingCeremony = PendingRegistration | PendingAuthentication;

export interface ReferenceRelyingPartyOptions {
  rpId?: string;
  rpName?: string;
  origin?: string;
  now?: () => number;
  challengeSeed?: string;
}

export interface AuthenticationRequest {
  userId?: string;
  allowCredentials?: Uint8Array[];
  userVerification?: UserVerification;
  mediation?: Mediation;
  extensions?: Record<string, { required?: boolean }>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

export class UnsupportedExtensionError extends Error {
  constructor(extension: string) {
    super(`unsupported_extension:${extension}`);
    this.name = "UnsupportedExtensionError";
  }
}

export class CeremonyAbortedError extends Error {
  constructor() {
    super("ceremony_aborted");
    this.name = "CeremonyAbortedError";
  }
}

export class CeremonyTimeoutError extends Error {
  constructor() {
    super("ceremony_timeout");
    this.name = "CeremonyTimeoutError";
  }
}

/**
 * In-memory reference RP for provider conformance tests.
 *
 * It intentionally has no HTTP or wall-clock dependency. Core-ts, rather than
 * authenticator-ts, verifies every response so the producer does not verify
 * its own cryptographic output.
 */
export class ReferenceRelyingParty {
  readonly rpId: string;
  readonly rpName: string;
  readonly origin: string;

  private readonly now: () => number;
  private readonly challengeSeed: string;
  private challengeSequence = 0;
  private ceremonySequence = 0;
  private readonly credentials = new Map<string, CredentialRecord>();
  private readonly ceremonies = new Map<string, PendingCeremony>();

  constructor(options: ReferenceRelyingPartyOptions = {}) {
    this.rpId = options.rpId ?? "rp.example.test";
    this.rpName = options.rpName ?? "Reference RP";
    this.origin = options.origin ?? `https://${this.rpId}`;
    this.now = options.now ?? (() => 1_000);
    this.challengeSeed = options.challengeSeed ?? "open-passkey-reference-rp-v1";
  }

  beginRegistration(input: { userId: string; userName: string; timeoutMs?: number }) {
    const ceremonyId = this.nextCeremonyId("registration");
    const challenge = this.nextChallenge();
    this.ceremonies.set(ceremonyId, {
      kind: "registration",
      challenge,
      userId: input.userId,
      userName: input.userName,
      expiresAt: this.now() + (input.timeoutMs ?? 30_000),
      consumed: false,
    });

    return {
      ceremonyId,
      challenge,
      rp: { id: this.rpId, name: this.rpName },
      user: {
        id: new TextEncoder().encode(input.userId),
        name: input.userName,
      },
      algorithms: [-7],
    };
  }

  finishRegistration(
    ceremonyId: string,
    credentialId: string,
    response: RegistrationResponse,
  ) {
    const pending = this.requireCeremony(ceremonyId, "registration");
    const result = verifyRegistration({
      rpId: this.rpId,
      expectedChallenge: bytes(pending.challenge),
      expectedOrigin: this.origin,
      clientDataJSON: response.clientDataJSON,
      attestationObject: response.attestationObject,
    });
    if (bytes(result.credentialId) !== credentialId) {
      throw new Error("credential_id_mismatch");
    }

    const record: CredentialRecord = {
      credentialId,
      userId: pending.userId,
      userName: pending.userName,
      publicKeyCose: result.publicKeyCose,
      signCount: result.signCount,
    };
    this.credentials.set(credentialId, record);
    pending.consumed = true;
    return record;
  }

  beginAuthentication(request: AuthenticationRequest = {}) {
    const unsupportedExtensions = Object.keys(request.extensions ?? {});
    for (const extension of unsupportedExtensions) {
      if (request.extensions?.[extension]?.required) {
        throw new UnsupportedExtensionError(extension);
      }
    }

    const allowed = request.allowCredentials?.map(bytes);
    const candidates = [...this.credentials.values()].filter((credential) => {
      if (request.userId !== undefined && credential.userId !== request.userId) return false;
      return allowed === undefined || allowed.includes(credential.credentialId);
    });
    const ceremonyId = this.nextCeremonyId("authentication");
    const challenge = this.nextChallenge();
    const mediation = request.mediation ?? "optional";
    const userVerification = request.userVerification ?? "preferred";
    this.ceremonies.set(ceremonyId, {
      kind: "authentication",
      challenge,
      expectedUserId: request.userId,
      candidates,
      userVerification,
      mediation,
      expiresAt: this.now() + (request.timeoutMs ?? 30_000),
      signal: request.signal,
      consumed: false,
    });

    return {
      ceremonyId,
      challenge,
      mediation,
      userVerification,
      candidates: candidates.map(({ credentialId, userId, userName }) => ({
        credentialId,
        userId,
        userName,
      })),
      extensions: {},
      unsupportedExtensions,
    };
  }

  selectCredential(ceremonyId: string, credentialId?: Uint8Array) {
    const pending = this.requireCeremony(ceremonyId, "authentication");
    if (pending.candidates.length === 0) throw new Error("credential_not_found");
    if (credentialId === undefined) {
      if (pending.candidates.length !== 1) throw new Error("credential_selection_required");
      return pending.candidates[0];
    }
    const selected = pending.candidates.find(
      (candidate) => candidate.credentialId === bytes(credentialId),
    );
    if (!selected) throw new Error("credential_not_allowed");
    return selected;
  }

  finishAuthentication(
    ceremonyId: string,
    credentialId: Uint8Array,
    response: CredentialResponse,
  ) {
    const pending = this.requireCeremony(ceremonyId, "authentication");
    const credential = this.selectCredential(ceremonyId, credentialId);
    if (response.userHandle === null) {
      if (pending.expectedUserId === undefined) throw new Error("user_handle_required");
    } else {
      const responseUserId = new TextDecoder().decode(
        Buffer.from(response.userHandle, "base64url"),
      );
      if (responseUserId !== credential.userId) throw new Error("user_handle_mismatch");
    }

    const result = verifyAuthentication({
      rpId: this.rpId,
      expectedChallenge: bytes(pending.challenge),
      expectedOrigin: this.origin,
      storedPublicKeyCose: credential.publicKeyCose,
      storedSignCount: credential.signCount,
      clientDataJSON: response.clientDataJSON,
      authenticatorData: response.authenticatorData,
      signature: response.signature,
      requireUserVerification: pending.userVerification === "required",
    });
    credential.signCount = result.signCount;
    pending.consumed = true;
    return { userId: credential.userId, ...result };
  }

  private requireCeremony<K extends PendingCeremony["kind"]>(
    ceremonyId: string,
    kind: K,
  ): Extract<PendingCeremony, { kind: K }> {
    const pending = this.ceremonies.get(ceremonyId);
    if (!pending || pending.kind !== kind || pending.consumed) {
      throw new Error("ceremony_not_pending");
    }
    if ("signal" in pending && pending.signal?.aborted) throw new CeremonyAbortedError();
    if (this.now() > pending.expiresAt) throw new CeremonyTimeoutError();
    return pending as Extract<PendingCeremony, { kind: K }>;
  }

  private nextChallenge(): Uint8Array {
    this.challengeSequence += 1;
    return Uint8Array.from(
      createHash("sha256")
        .update(`${this.challengeSeed}:${this.challengeSequence}`)
        .digest(),
    );
  }

  private nextCeremonyId(kind: PendingCeremony["kind"]): string {
    this.ceremonySequence += 1;
    return `${kind}-${this.ceremonySequence}`;
  }
}

export function bytes(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}
