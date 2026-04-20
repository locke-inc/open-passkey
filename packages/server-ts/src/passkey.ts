import {
  verifyRegistration,
  verifyAuthentication,
  COSE_ALG_ES256,
  COSE_ALG_MLDSA65,
  COSE_ALG_COMPOSITE_MLDSA65_ES256,
} from "@open-passkey/core";
import { base64urlEncode, base64urlDecode } from "./base64url.js";
import type { SessionConfig, SessionTokenData } from "./session.js";
import {
  validateSessionConfig,
  createSessionToken,
  validateSessionToken,
} from "./session.js";
import type {
  PasskeyConfig,
  StoredCredential,
  BeginRegistrationRequest,
  BeginRegistrationResponse,
  FinishRegistrationRequest,
  FinishRegistrationResponse,
  BeginAuthenticationRequest,
  BeginAuthenticationResponse,
  FinishAuthenticationRequest,
  FinishAuthenticationResponse,
} from "./types.js";

export class PasskeyError extends Error {
  constructor(
    public readonly statusCode: number,
    message: string,
  ) {
    super(message);
    this.name = "PasskeyError";
  }
}

export class Passkey {
  private readonly rpId: string;
  private readonly rpDisplayName: string;
  private readonly origin: string;
  private readonly challengeLength: number;
  private readonly challengeTimeout: number;
  private readonly challengeStore: PasskeyConfig["challengeStore"];
  private readonly credentialStore: PasskeyConfig["credentialStore"];
  private readonly allowMultipleCredentials: boolean;
  private readonly sessionConfig?: SessionConfig;
  private readonly prfSalt?: Uint8Array;

  constructor(config: PasskeyConfig) {
    if (!config.rpId) throw new PasskeyError(500, "rpId is required");
    if (!config.origin) throw new PasskeyError(500, "origin is required");
    if (!config.challengeStore) throw new PasskeyError(500, "challengeStore is required");
    if (!config.credentialStore) throw new PasskeyError(500, "credentialStore is required");
    if (/[:\/]/.test(config.rpId)) {
      throw new PasskeyError(500, `rpId must be a bare domain (got "${config.rpId}")`);
    }
    if (!config.origin.startsWith("https://") && !config.origin.startsWith("http://")) {
      throw new PasskeyError(500, `origin must start with https:// or http:// (got "${config.origin}")`);
    }
    if (config.prfSalt && config.prfSalt.length !== 32) {
      throw new PasskeyError(500, `prfSalt must be exactly 32 bytes (got ${config.prfSalt.length})`);
    }

    if (config.session) {
      validateSessionConfig(config.session);
      this.sessionConfig = config.session;
    }

    this.rpId = config.rpId;
    this.rpDisplayName = config.rpDisplayName;
    this.origin = config.origin;
    this.challengeStore = config.challengeStore;
    this.credentialStore = config.credentialStore;
    this.challengeLength = config.challengeLength ?? 32;
    this.challengeTimeout = config.challengeTimeout ?? 300_000;
    this.allowMultipleCredentials = config.allowMultipleCredentials ?? false;
    this.prfSalt = config.prfSalt;
  }

  private generateChallenge(): string {
    const buf = new Uint8Array(this.challengeLength);
    crypto.getRandomValues(buf);
    return base64urlEncode(buf);
  }

  async beginRegistration(req: BeginRegistrationRequest): Promise<BeginRegistrationResponse> {
    if (!req.userId || !req.username) {
      throw new PasskeyError(400, "userId is required");
    }

    const existing = await this.credentialStore.getByUser(req.userId);

    if (!this.allowMultipleCredentials && existing.length > 0) {
      throw new PasskeyError(409, "user already registered");
    }

    const challenge = this.generateChallenge();

    const prfSalt = this.prfSalt ?? crypto.getRandomValues(new Uint8Array(32));

    const challengeData = JSON.stringify({
      challenge,
      prfSalt: base64urlEncode(prfSalt),
    });
    await this.challengeStore.store(req.userId, challengeData, this.challengeTimeout);

    const options: BeginRegistrationResponse = {
      challenge,
      rp: { id: this.rpId, name: this.rpDisplayName },
      user: {
        id: base64urlEncode(new TextEncoder().encode(req.userId)),
        name: req.username,
        displayName: req.username,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: COSE_ALG_COMPOSITE_MLDSA65_ES256 },
        { type: "public-key", alg: COSE_ALG_MLDSA65 },
        { type: "public-key", alg: COSE_ALG_ES256 },
      ],
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
      timeout: this.challengeTimeout,
      attestation: "none",
      extensions: {
        prf: {
          eval: { first: base64urlEncode(prfSalt) },
        },
      },
    };

    if (existing.length > 0) {
      options.excludeCredentials = existing.map((c) => ({
        type: "public-key" as const,
        id: base64urlEncode(c.credentialId),
      }));
    }

    return options;
  }

  async finishRegistration(req: FinishRegistrationRequest): Promise<FinishRegistrationResponse> {
    const challengeData = await this.challengeStore.consume(req.userId);
    if (!challengeData) {
      throw new PasskeyError(400, "challenge not found or expired");
    }

    const stored = JSON.parse(challengeData) as { challenge: string; prfSalt: string };

    const result = verifyRegistration({
      rpId: this.rpId,
      expectedChallenge: stored.challenge,
      expectedOrigin: this.origin,
      clientDataJSON: req.credential.response.clientDataJSON,
      attestationObject: req.credential.response.attestationObject,
    });

    const prfEnabled = req.prfSupported === true;
    const cred: StoredCredential = {
      credentialId: result.credentialId,
      publicKeyCose: result.publicKeyCose,
      signCount: result.signCount,
      userId: req.userId,
      prfSupported: false,
    };

    if (prfEnabled) {
      cred.prfSalt = base64urlDecode(stored.prfSalt);
      cred.prfSupported = true;
    }

    await this.credentialStore.store(cred);

    const resp: FinishRegistrationResponse = {
      credentialId: base64urlEncode(result.credentialId),
      registered: true,
      prfSupported: prfEnabled,
    };
    if (this.sessionConfig) {
      resp.sessionToken = createSessionToken(req.userId, this.sessionConfig);
    }
    return resp;
  }

  /**
   * When userId is provided, the response includes PRF salts (extensions.prf.evalByCredential)
   * for vault support. When omitted (discoverable flow) and a global prfSalt is configured,
   * the response includes prf.eval.first with the static salt — enabling PRF output for any
   * credential the user selects. When omitted and no prfSalt is set, PRF output will be
   * undefined and vault() will be unavailable on the client.
   */
  async beginAuthentication(req: BeginAuthenticationRequest): Promise<BeginAuthenticationResponse> {
    const challenge = this.generateChallenge();

    const challengeKey = req.userId || challenge;
    await this.challengeStore.store(challengeKey, challenge, this.challengeTimeout);

    const options: BeginAuthenticationResponse = {
      challenge,
      rpId: this.rpId,
      timeout: this.challengeTimeout,
      userVerification: "preferred",
    };

    if (req.userId) {
      const allowCredentials: Array<{ type: string; id: string }> = [];
      const evalByCredential: Record<string, { first: string }> = {};
      let hasPRF = false;

      const creds = await this.credentialStore.getByUser(req.userId);
      for (const c of creds) {
        const credIdEncoded = base64urlEncode(c.credentialId);
        allowCredentials.push({ type: "public-key", id: credIdEncoded });
        if (c.prfSupported && c.prfSalt) {
          evalByCredential[credIdEncoded] = {
            first: base64urlEncode(c.prfSalt),
          };
          hasPRF = true;
        }
      }

      options.allowCredentials = allowCredentials;
      if (hasPRF) {
        options.extensions = { prf: { evalByCredential } };
      }
    } else if (this.prfSalt) {
      // Discoverable credential flow with global static PRF salt.
      // Because the salt is the same for all credentials, we can include it
      // as prf.eval.first without knowing which credential will be selected.
      options.extensions = { prf: { eval: { first: base64urlEncode(this.prfSalt) } } };
    }

    return options;
  }

  async finishAuthentication(req: FinishAuthenticationRequest): Promise<FinishAuthenticationResponse> {
    const challenge = await this.challengeStore.consume(req.userId);
    if (!challenge) {
      throw new PasskeyError(400, "challenge not found or expired");
    }

    const credIdBytes = base64urlDecode(req.credential.id);
    const stored = await this.credentialStore.get(credIdBytes);
    if (!stored) {
      throw new PasskeyError(400, "credential not found");
    }

    // Verify userHandle matches credential owner (discoverable flow)
    if (req.credential.response.userHandle) {
      const userHandleBytes = base64urlDecode(req.credential.response.userHandle);
      const userHandleStr = new TextDecoder().decode(userHandleBytes);
      if (userHandleStr !== stored.userId) {
        throw new PasskeyError(400, "userHandle does not match credential owner");
      }
    }

    const result = verifyAuthentication({
      rpId: this.rpId,
      expectedChallenge: challenge,
      expectedOrigin: this.origin,
      storedPublicKeyCose: stored.publicKeyCose,
      storedSignCount: stored.signCount,
      clientDataJSON: req.credential.response.clientDataJSON,
      authenticatorData: req.credential.response.authenticatorData,
      signature: req.credential.response.signature,
    });

    stored.signCount = result.signCount;
    await this.credentialStore.update(stored);

    const resp: FinishAuthenticationResponse = {
      userId: stored.userId,
      credentialId: req.credential.id,
      authenticated: true,
    };
    if (stored.prfSupported) {
      resp.prfSupported = true;
    }
    if (this.sessionConfig) {
      resp.sessionToken = createSessionToken(stored.userId, this.sessionConfig);
    }
    return resp;
  }

  getSessionTokenData(token: string): SessionTokenData {
    if (!this.sessionConfig) {
      throw new PasskeyError(500, "session is not configured");
    }
    return validateSessionToken(token, this.sessionConfig);
  }

  getSessionConfig(): SessionConfig | undefined {
    return this.sessionConfig;
  }
}
