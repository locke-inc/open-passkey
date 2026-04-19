export function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(str: string): ArrayBuffer {
  // Restore base64 padding
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export const PROVIDERS = {
  "locke-gateway": "https://gateway.locke.id/passkey",
} as const;

export type ProviderName = keyof typeof PROVIDERS;

export interface PasskeyClientConfig {
  /** Direct URL to passkey API (e.g., "/passkey" for self-hosted). Mutually exclusive with provider. */
  baseUrl?: string;
  /** Named hosted provider. Resolves to a known URL. Requires rpId. */
  provider?: ProviderName;
  /** Relying Party ID sent to hosted providers (e.g., "app.example.com"). Required when using provider. */
  rpId?: string;
}

interface BeginRegistrationResponse {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  authenticatorSelection: { residentKey: string; userVerification: string };
  timeout: number;
  attestation: string;
  extensions?: Record<string, unknown>;
}

interface BeginAuthenticationResponse {
  challenge: string;
  rpId: string;
  timeout: number;
  userVerification: string;
  allowCredentials?: Array<{ type: string; id: string }>;
  extensions?: Record<string, unknown>;
}

export interface RegistrationResult {
  credentialId: string;
  registered: boolean;
  prfSupported: boolean;
  prfOutput?: ArrayBuffer;
  sessionToken?: string;
}

export interface AuthenticationResult {
  userId: string;
  authenticated: boolean;
  prfSupported?: boolean;
  prfOutput?: ArrayBuffer;
  sessionToken?: string;
}

// Authenticated fetch: prefers Bearer token when available, falls back to cookie.
function authFetch(
  url: string,
  sessionToken: string | null,
  init?: RequestInit,
): Promise<Response> {
  if (sessionToken) {
    const headers = new Headers(init?.headers);
    headers.set("Authorization", `Bearer ${sessionToken}`);
    return fetch(url, { ...init, headers });
  }
  return fetch(url, { ...init, credentials: "include" });
}

export class PasskeyClient {
  private readonly baseUrl: string;
  private readonly rpId?: string;
  private prfKey: ArrayBuffer | null = null;
  private sessionToken: string | null = null;

  constructor(config: PasskeyClientConfig) {
    if (config.baseUrl && config.provider) {
      throw new Error("Specify either baseUrl or provider, not both");
    }

    if (config.baseUrl) {
      this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    } else if (config.provider) {
      const url = PROVIDERS[config.provider];
      if (!url) {
        throw new Error(`Unknown provider: "${config.provider}". Available: ${Object.keys(PROVIDERS).join(", ")}`);
      }
      if (!config.rpId) {
        throw new Error(`rpId is required when using provider "${config.provider}"`);
      }
      this.baseUrl = url;
      this.rpId = config.rpId;
    } else {
      throw new Error(
        'PasskeyClient requires either baseUrl (self-hosted) or provider (hosted). Example:\n' +
        '  new PasskeyClient({ provider: "locke-gateway", rpId: "example.com" })\n' +
        '  new PasskeyClient({ baseUrl: "/passkey" })'
      );
    }
  }

  async register(
    userId: string,
    username: string,
  ): Promise<RegistrationResult> {
    // Step 1: Get registration options from server
    const beginBody: Record<string, string> = { userId, username };
    if (this.rpId) beginBody.rpId = this.rpId;

    const beginRes = await fetch(`${this.baseUrl}/register/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(beginBody),
      credentials: "include",
    });
    if (!beginRes.ok) {
      const err = await beginRes.json();
      throw new Error(err.error || "Failed to begin registration");
    }
    const options: BeginRegistrationResponse = await beginRes.json();

    // Step 2: Convert base64url strings to ArrayBuffers for WebAuthn API
    const createOptions: CredentialCreationOptions = {
      publicKey: {
        challenge: base64urlDecode(options.challenge),
        rp: options.rp,
        user: {
          id: base64urlDecode(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName,
        },
        pubKeyCredParams: options.pubKeyCredParams.map((p) => ({
          type: p.type as PublicKeyCredentialType,
          alg: p.alg,
        })),
        authenticatorSelection: {
          residentKey: options.authenticatorSelection.residentKey as ResidentKeyRequirement,
          userVerification: options.authenticatorSelection.userVerification as UserVerificationRequirement,
        },
        timeout: options.timeout,
        attestation: options.attestation as AttestationConveyancePreference,
      },
    };

    // Handle PRF extension — decode base64url salt values to ArrayBuffer
    if (options.extensions?.prf) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const prf = structuredClone(options.extensions.prf) as any;
      if (prf.eval) {
        if (prf.eval.first) prf.eval.first = base64urlDecode(prf.eval.first);
        if (prf.eval.second) prf.eval.second = base64urlDecode(prf.eval.second);
      }
      createOptions.publicKey!.extensions = { prf };
    }

    // Step 3: Call WebAuthn API
    const credential = (await navigator.credentials.create(createOptions)) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error("Credential creation returned null");
    }

    const response = credential.response as AuthenticatorAttestationResponse;

    // Check PRF support and capture PRF output from extension results
    const extensionResults = credential.getClientExtensionResults();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prfExt = (extensionResults as any)?.prf;
    const prfSupported = !!prfExt?.enabled;
    const prfOutput: ArrayBuffer | null = prfExt?.results?.first ?? null;
    if (prfOutput) {
      this.prfKey = prfOutput;
    }

    // Step 4: Encode response back to base64url and POST to server
    const finishRes = await fetch(`${this.baseUrl}/register/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId,
        prfSupported,
        credential: {
          id: credential.id,
          rawId: base64urlEncode(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: base64urlEncode(response.clientDataJSON),
            attestationObject: base64urlEncode(response.attestationObject),
          },
        },
      }),
      credentials: "include",
    });
    if (!finishRes.ok) {
      const err = await finishRes.json();
      throw new Error(err.error || "Failed to finish registration");
    }

    const result: RegistrationResult = await finishRes.json();
    if (result.sessionToken) {
      this.sessionToken = result.sessionToken;
    }
    if (prfOutput) {
      result.prfOutput = prfOutput;
    }
    return result;
  }

  /**
   * Authenticate with a passkey.
   *
   * @param userId - The user identifier (e.g., email). When provided, the server looks
   *   up the user's credentials and includes their per-credential PRF salts in the
   *   WebAuthn request options (evalByCredential). When omitted, the browser uses
   *   discoverable credentials (the OS passkey picker). If the server is configured
   *   with a global static PRF salt, PRF output is still available in discoverable
   *   mode via prf.eval.first. Without a global salt, PRF output is unavailable when
   *   userId is omitted.
   */
  async authenticate(
    userId?: string,
  ): Promise<AuthenticationResult> {
    // Step 1: Get authentication options from server
    const beginBody: Record<string, string> = {};
    if (userId) beginBody.userId = userId;
    if (this.rpId) beginBody.rpId = this.rpId;

    const beginRes = await fetch(`${this.baseUrl}/login/begin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(beginBody),
      credentials: "include",
    });
    if (!beginRes.ok) {
      const err = await beginRes.json();
      throw new Error(err.error || "Failed to begin authentication");
    }
    const options: BeginAuthenticationResponse = await beginRes.json();

    // Step 2: Convert base64url strings to ArrayBuffers for WebAuthn API
    const getOptions: CredentialRequestOptions = {
      publicKey: {
        challenge: base64urlDecode(options.challenge),
        rpId: options.rpId,
        timeout: options.timeout,
        userVerification: options.userVerification as UserVerificationRequirement,
      },
    };

    if (options.allowCredentials) {
      getOptions.publicKey!.allowCredentials = options.allowCredentials.map((c) => ({
        type: c.type as PublicKeyCredentialType,
        id: base64urlDecode(c.id),
      }));
    }

    // Handle PRF extension — decode base64url salt values to ArrayBuffer
    if (options.extensions?.prf) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const prf = structuredClone(options.extensions.prf) as any;
      if (prf.evalByCredential) {
        for (const vals of Object.values(prf.evalByCredential) as any[]) {
          if (vals.first) vals.first = base64urlDecode(vals.first);
          if (vals.second) vals.second = base64urlDecode(vals.second);
        }
      }
      if (prf.eval) {
        if (prf.eval.first) prf.eval.first = base64urlDecode(prf.eval.first);
        if (prf.eval.second) prf.eval.second = base64urlDecode(prf.eval.second);
      }
      getOptions.publicKey!.extensions = { prf };
    }

    // Step 3: Call WebAuthn API
    const credential = (await navigator.credentials.get(getOptions)) as PublicKeyCredential | null;
    if (!credential) {
      throw new Error("Credential assertion returned null");
    }

    const response = credential.response as AuthenticatorAssertionResponse;

    // Extract PRF output if available (for vault encryption key derivation)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const prfResults = (credential.getClientExtensionResults() as any)?.prf?.results;
    const prfOutput: ArrayBuffer | null = prfResults?.first ?? null;

    // Build finish payload
    // In discoverable flow (no userId), use the challenge as the lookup key —
    // the server stores the challenge under the challenge value itself when no userId is provided.
    const finishPayload: Record<string, unknown> = {
      userId: userId || options.challenge,
      credential: {
        id: credential.id,
        rawId: base64urlEncode(credential.rawId),
        type: credential.type,
        response: {
          clientDataJSON: base64urlEncode(response.clientDataJSON),
          authenticatorData: base64urlEncode(response.authenticatorData),
          signature: base64urlEncode(response.signature),
          ...(response.userHandle ? { userHandle: base64urlEncode(response.userHandle) } : {}),
        },
      },
    };

    // Step 4: POST result to server
    const finishRes = await fetch(`${this.baseUrl}/login/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(finishPayload),
      credentials: "include",
    });
    if (!finishRes.ok) {
      const err = await finishRes.json();
      throw new Error(err.error || "Failed to finish authentication");
    }

    const result: AuthenticationResult = await finishRes.json();
    if (result.sessionToken) {
      this.sessionToken = result.sessionToken;
    }
    if (prfOutput) {
      this.prfKey = prfOutput;
      result.prfOutput = prfOutput;
    }
    return result;
  }

  async getSession(): Promise<AuthenticationResult | null> {
    const res = await authFetch(`${this.baseUrl}/session`, this.sessionToken);
    if (res.status === 401) return null;
    if (!res.ok) throw new Error("Failed to get session");
    return res.json();
  }

  async logout(): Promise<void> {
    await authFetch(`${this.baseUrl}/logout`, this.sessionToken, { method: "POST" });
    this.sessionToken = null;
    this.prfKey = null;
    await Vault.clear();
  }

  /**
   * Create a Vault backed by the PRF-derived encryption key from the last authenticate() call.
   *
   * Throws if authenticate() was not called with a userId, or if the authenticator
   * does not support the PRF extension. Use Vault.persistKey() after creation to
   * store the non-extractable CryptoKey in IndexedDB so the vault survives page
   * refreshes without re-authentication. Use Vault.restore() on page load to
   * recover a previously persisted vault.
   */
  vault(): Vault {
    if (!this.prfKey) {
      throw new Error(
        "Vault requires PRF support. Call authenticate() first with a PRF-capable authenticator."
      );
    }
    return new Vault(this.prfKey, this.baseUrl, this.sessionToken);
  }
}

export class Vault {
  private static readonly DB_NAME = "open-passkey";
  private static readonly STORE_NAME = "vault-keys";
  private static readonly ENC_KEY_ID = "encryption-key";
  private static readonly HMAC_KEY_ID = "hmac-key";

  private encryptionKey: Promise<CryptoKey>;
  private hmacKey: Promise<CryptoKey>;
  private baseUrl: string;
  private sessionToken: string | null;

  constructor(prfOutput: ArrayBuffer, baseUrl: string, sessionToken?: string | null) {
    this.baseUrl = baseUrl;
    this.sessionToken = sessionToken ?? null;
    const keys = this.deriveKeys(prfOutput);
    this.encryptionKey = keys.then((k) => k.encryption);
    this.hmacKey = keys.then((k) => k.hmac);
  }

  /** Create a Vault from previously persisted CryptoKeys (e.g., restored from IndexedDB). */
  static fromCryptoKeys(
    encryptionKey: CryptoKey,
    hmacKey: CryptoKey,
    baseUrl: string,
    sessionToken?: string | null,
  ): Vault {
    const v = Object.create(Vault.prototype) as Vault;
    v.baseUrl = baseUrl;
    v.sessionToken = sessionToken ?? null;
    v.encryptionKey = Promise.resolve(encryptionKey);
    v.hmacKey = Promise.resolve(hmacKey);
    return v;
  }

  /** Persist the derived CryptoKeys to IndexedDB. The keys remain non-extractable. */
  async persistKey(): Promise<void> {
    const [encKey, hmKey] = await Promise.all([this.encryptionKey, this.hmacKey]);
    const db = await Vault.openDB();
    try {
      const tx = db.transaction(Vault.STORE_NAME, "readwrite");
      const store = tx.objectStore(Vault.STORE_NAME);
      store.put(encKey, Vault.ENC_KEY_ID);
      store.put(hmKey, Vault.HMAC_KEY_ID);
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      });
    } finally {
      db.close();
    }
  }

  /** Restore a Vault from previously persisted CryptoKeys in IndexedDB. Returns null if not found. */
  static async restore(baseUrl: string, sessionToken?: string | null): Promise<Vault | null> {
    try {
      const db = await Vault.openDB();
      try {
        const tx = db.transaction(Vault.STORE_NAME, "readonly");
        const store = tx.objectStore(Vault.STORE_NAME);
        const encKey = await new Promise<CryptoKey | undefined>((resolve, reject) => {
          const req = store.get(Vault.ENC_KEY_ID);
          req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
          req.onerror = () => reject(req.error);
        });
        const hmKey = await new Promise<CryptoKey | undefined>((resolve, reject) => {
          const req = store.get(Vault.HMAC_KEY_ID);
          req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
          req.onerror = () => reject(req.error);
        });
        if (!encKey || !hmKey) return null;
        return Vault.fromCryptoKeys(encKey, hmKey, baseUrl, sessionToken);
      } finally {
        db.close();
      }
    } catch {
      return null;
    }
  }

  /** Clear the persisted CryptoKeys from IndexedDB. */
  static async clear(): Promise<void> {
    try {
      const db = await Vault.openDB();
      try {
        const tx = db.transaction(Vault.STORE_NAME, "readwrite");
        tx.objectStore(Vault.STORE_NAME).clear();
        await new Promise<void>((resolve, reject) => {
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        });
      } finally {
        db.close();
      }
    } catch {
      // Ignore — nothing to clear
    }
  }

  private static openDB(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(Vault.DB_NAME, 1);
      req.onupgradeneeded = () => {
        req.result.createObjectStore(Vault.STORE_NAME);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async deriveKeys(
    prfOutput: ArrayBuffer,
  ): Promise<{ encryption: CryptoKey; hmac: CryptoKey }> {
    const keyMaterial = await crypto.subtle.importKey(
      "raw", prfOutput, "HKDF", false, ["deriveKey"],
    );
    const [encryption, hmac] = await Promise.all([
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new TextEncoder().encode("open-passkey-vault"),
          info: new TextEncoder().encode("aes-256-gcm"),
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
      ),
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new TextEncoder().encode("open-passkey-vault"),
          info: new TextEncoder().encode("vault-key-hmac"),
        },
        keyMaterial,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign"],
      ),
    ]);
    return { encryption, hmac };
  }

  /** HMAC the key name so the server only sees an opaque token. */
  private async hashKey(key: string): Promise<string> {
    const hk = await this.hmacKey;
    const sig = await crypto.subtle.sign("HMAC", hk, new TextEncoder().encode(key));
    return base64urlEncode(sig);
  }

  async setItem(key: string, value: string): Promise<void> {
    const [k, hashedKey] = await Promise.all([this.encryptionKey, this.hashKey(key)]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      k,
      new TextEncoder().encode(value),
    );
    const packed = new Uint8Array(12 + ciphertext.byteLength);
    packed.set(iv, 0);
    packed.set(new Uint8Array(ciphertext), 12);

    const res = await authFetch(
      `${this.baseUrl}/vault/${hashedKey}`,
      this.sessionToken,
      {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ value: base64urlEncode(packed.buffer) }),
      },
    );
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Failed to set vault item" }));
      throw new Error(err.error || "Failed to set vault item");
    }
  }

  async getItem(key: string): Promise<string | null> {
    const hashedKey = await this.hashKey(key);
    const res = await authFetch(
      `${this.baseUrl}/vault/${hashedKey}`,
      this.sessionToken,
    );
    if (res.status === 404) return null;
    if (!res.ok) throw new Error("Failed to get vault item");

    const { value } = await res.json();
    const packed = new Uint8Array(base64urlDecode(value));
    const iv = packed.slice(0, 12);
    const ciphertext = packed.slice(12);

    const k = await this.encryptionKey;
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      k,
      ciphertext,
    );
    return new TextDecoder().decode(plaintext);
  }

  async removeItem(key: string): Promise<void> {
    const hashedKey = await this.hashKey(key);
    await authFetch(
      `${this.baseUrl}/vault/${hashedKey}`,
      this.sessionToken,
      { method: "DELETE" },
    );
  }
}
