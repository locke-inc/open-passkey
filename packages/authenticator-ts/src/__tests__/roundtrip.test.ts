import { describe, it, expect } from "vitest";
import { createCredential, getAssertion, p1363ToDer } from "../index.js";
import type { CreateCredentialInput } from "../index.js";
import { verifyRegistration, verifyAuthentication } from "../../../core-ts/src/index.js";

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(value: string): Uint8Array {
  let padded = value.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const VERIFIED_SYNCED_CEREMONY = {
  userPresent: true,
  userVerified: true,
  backupEligible: true,
  backupState: true,
} as const;

function randomChallenge(): Uint8Array {
  const buf = new Uint8Array(32);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

describe("Registration round-trip", () => {
  it("reports resident credProps without setting authenticator extension data", async () => {
    const challenge = randomChallenge();

    const result = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1, 2, 3, 4]),
      userName: "testuser",
      challenge,
      origin: ORIGIN,
      algorithms: [-7],
      extensions: { credProps: true },
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    const regResult = verifyRegistration({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      clientDataJSON: result.response.clientDataJSON,
      attestationObject: result.response.attestationObject,
    });

    expect(regResult.flags).toBe(0x5d); // UP + UV + BE + BS + AT
    expect(regResult.publicKeyCose).toEqual(result.publicKeyCose);
    expect(result.clientExtensionResults).toEqual({ credProps: { rk: true } });
  });

  it("serializes explicit cross-origin context", async () => {
    const result = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "testuser",
      challenge: randomChallenge(),
      origin: "https://login.example.com",
      topOrigin: "https://embedder.test",
      crossOrigin: true,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    const clientData = JSON.parse(
      new TextDecoder().decode(base64urlDecode(result.response.clientDataJSON)),
    );
    expect(clientData.crossOrigin).toBe(true);
    expect(clientData.topOrigin).toBe("https://embedder.test");
  });

  it("encodes only the supplied ceremony facts", async () => {
    const challenge = randomChallenge();

    const result = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1, 2, 3, 4]),
      userName: "testuser",
      challenge,
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: {
        userPresent: true,
        userVerified: false,
        backupEligible: true,
        backupState: false,
      },
    });

    const regResult = verifyRegistration({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      clientDataJSON: result.response.clientDataJSON,
      attestationObject: result.response.attestationObject,
    });

    expect(regResult.flags).toBe(0x49); // UP + BE + AT
    expect(regResult.backupEligible).toBe(true);
    expect(regResult.backupState).toBe(false);
  });

  it("creates a credential that core-ts verifies", async () => {
    const challenge = randomChallenge();
    const userId = new Uint8Array([1, 2, 3, 4]);

    const result = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId,
      userName: "testuser",
      challenge,
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    // Verify with core-ts
    const regResult = verifyRegistration({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      clientDataJSON: result.response.clientDataJSON,
      attestationObject: result.response.attestationObject,
    });

    expect(regResult.credentialId).toEqual(result.credential.credentialId);
    expect(regResult.signCount).toBe(0);
    expect(regResult.attestationFormat).toBe("none");
    expect(regResult.backupEligible).toBe(true);
    expect(regResult.backupState).toBe(true);
  });
});

describe("Authentication round-trip", () => {
  it("does not set ED when no authentication extension was negotiated", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([5]),
      userName: "testuser",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });
    const challenge = randomChallenge();

    const assertion = await getAssertion({
      rpId: RP_ID,
      challenge,
      origin: ORIGIN,
      credential: createResult.credential,
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });
    const authData = base64urlDecode(assertion.response.authenticatorData);

    expect(authData[32]).toBe(0x1d); // UP + UV + BE + BS
    expect(authData).toHaveLength(37);
    expect(() => verifyAuthentication({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      storedPublicKeyCose: createResult.credential.publicKeyCose,
      storedSignCount: 0,
      clientDataJSON: assertion.response.clientDataJSON,
      authenticatorData: assertion.response.authenticatorData,
      signature: assertion.response.signature,
    })).not.toThrow();
  });

  it("returns a nullable user handle without changing signature verification", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([5, 6, 7, 8]),
      userName: "testuser",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });
    const challenge = randomChallenge();

    const assertion = await getAssertion({
      rpId: RP_ID,
      challenge,
      origin: ORIGIN,
      credential: { ...createResult.credential, userId: null },
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    expect(assertion.response.userHandle).toBeNull();
    expect(() => verifyAuthentication({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      storedPublicKeyCose: createResult.credential.publicKeyCose,
      storedSignCount: 0,
      clientDataJSON: assertion.response.clientDataJSON,
      authenticatorData: assertion.response.authenticatorData,
      signature: assertion.response.signature,
    })).not.toThrow();
  });

  it("encodes supplied ceremony facts and always reports a zero counter", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([5, 6, 7, 8]),
      userName: "testuser",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: {
        userPresent: true,
        userVerified: false,
        backupEligible: true,
        backupState: true,
      },
    });

    const challenge = randomChallenge();
    const assertionResult = await getAssertion({
      rpId: RP_ID,
      challenge,
      origin: ORIGIN,
      credential: { ...createResult.credential, signCount: 42 },
      ceremony: {
        userPresent: true,
        userVerified: false,
        backupEligible: true,
        backupState: false,
      },
    });

    const authResult = verifyAuthentication({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(challenge),
      expectedOrigin: ORIGIN,
      storedPublicKeyCose: createResult.credential.publicKeyCose,
      storedSignCount: 0,
      clientDataJSON: assertionResult.response.clientDataJSON,
      authenticatorData: assertionResult.response.authenticatorData,
      signature: assertionResult.response.signature,
    });

    expect(authResult.flags).toBe(0x09); // UP + BE
    expect(authResult.signCount).toBe(0);
    expect(assertionResult.updatedCredential.signCount).toBe(0);
  });

  it("creates an assertion that core-ts verifies", async () => {
    // First create a credential
    const regChallenge = randomChallenge();
    const userId = new Uint8Array([5, 6, 7, 8]);

    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId,
      userName: "testuser",
      challenge: regChallenge,
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    // Now create an assertion
    const authChallenge = randomChallenge();
    const assertionResult = await getAssertion({
      rpId: RP_ID,
      challenge: authChallenge,
      origin: ORIGIN,
      credential: createResult.credential,
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    // Verify with core-ts
    const authResult = verifyAuthentication({
      rpId: RP_ID,
      expectedChallenge: base64urlEncode(authChallenge),
      expectedOrigin: ORIGIN,
      storedPublicKeyCose: createResult.credential.publicKeyCose,
      storedSignCount: 0,
      clientDataJSON: assertionResult.response.clientDataJSON,
      authenticatorData: assertionResult.response.authenticatorData,
      signature: assertionResult.response.signature,
    });

    expect(authResult.signCount).toBe(0);
    expect(authResult.backupEligible).toBe(true);
    expect(authResult.backupState).toBe(true);
    expect(assertionResult.updatedCredential.signCount).toBe(0);
  });

  it("keeps the sign count at zero across multiple assertions", async () => {
    const regChallenge = randomChallenge();
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([9, 10]),
      userName: "testuser",
      challenge: regChallenge,
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    let credential = createResult.credential;

    for (let i = 1; i <= 3; i++) {
      const challenge = randomChallenge();
      const assertion = await getAssertion({
        rpId: RP_ID,
        challenge,
        origin: ORIGIN,
        credential,
        ceremony: VERIFIED_SYNCED_CEREMONY,
      });

      const authResult = verifyAuthentication({
        rpId: RP_ID,
        expectedChallenge: base64urlEncode(challenge),
        expectedOrigin: ORIGIN,
        storedPublicKeyCose: createResult.credential.publicKeyCose,
        storedSignCount: credential.signCount,
        clientDataJSON: assertion.response.clientDataJSON,
        authenticatorData: assertion.response.authenticatorData,
        signature: assertion.response.signature,
      });

      expect(authResult.signCount).toBe(0);
      expect(assertion.updatedCredential.signCount).toBe(0);
      credential = assertion.updatedCredential;
    }
  });
});

describe("P1363 to DER conversion", () => {
  it("produces valid DER structure", async () => {
    // Create a credential and assertion to test the DER output
    const challenge = randomChallenge();
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([11, 12]),
      userName: "testuser",
      challenge,
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    const authChallenge = randomChallenge();
    const assertion = await getAssertion({
      rpId: RP_ID,
      challenge: authChallenge,
      origin: ORIGIN,
      credential: createResult.credential,
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    // Decode the base64url signature and verify it's valid DER SEQUENCE
    const sigB64 = assertion.response.signature;
    let padded = sigB64.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) padded += "=";
    const sigBytes = new Uint8Array(
      atob(padded).split("").map((c) => c.charCodeAt(0)),
    );

    // DER: 0x30 (SEQUENCE) || length || 0x02 (INTEGER) r || 0x02 (INTEGER) s
    expect(sigBytes[0]).toBe(0x30); // SEQUENCE
    const seqLen = sigBytes[1];
    expect(sigBytes.length).toBe(2 + seqLen);

    // First INTEGER (r)
    expect(sigBytes[2]).toBe(0x02);
    const rLen = sigBytes[3];
    // Second INTEGER (s)
    const sOffset = 4 + rLen;
    expect(sigBytes[sOffset]).toBe(0x02);
  });
});

describe("createCredential edge cases", () => {
  it("rejects a public suffix as an RP ID", async () => {
    await expect(
      createCredential({
        rpId: "com",
        rpName: "Invalid public suffix",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://shop.example.com",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("RP ID is not a registrable domain suffix");
  });

  it("rejects a multi-label public suffix as an RP ID", async () => {
    await expect(
      createCredential({
        rpId: "co.uk",
        rpName: "Invalid public suffix",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://login.example.co.uk",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("RP ID is not a registrable domain suffix");
  });

  it("rejects a private public suffix as an RP ID", async () => {
    await expect(
      createCredential({
        rpId: "github.io",
        rpName: "Invalid private suffix",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://login.tenant.github.io",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("RP ID is not a registrable domain suffix");
  });

  it("rejects a PSL wildcard-derived suffix as an RP ID", async () => {
    await expect(
      createCredential({
        rpId: "bar.ck",
        rpName: "Invalid wildcard suffix",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://foo.bar.ck",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("RP ID is not a registrable domain suffix");
  });

  it("accepts an ICANN registrable parent RP ID", async () => {
    await expect(
      createCredential({
        rpId: "example.co.uk",
        rpName: "Example UK",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://login.example.co.uk",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).resolves.toMatchObject({ credential: { rpId: "example.co.uk" } });
  });

  it("accepts a tenant domain above a private public suffix", async () => {
    await expect(
      createCredential({
        rpId: "tenant.github.io",
        rpName: "GitHub Pages tenant",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "https://login.tenant.github.io",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).resolves.toMatchObject({ credential: { rpId: "tenant.github.io" } });
  });

  it("allows HTTP only for an exact localhost origin", async () => {
    await expect(
      createCredential({
        rpId: "localhost",
        rpName: "Local development",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "http://localhost:3000",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).resolves.toMatchObject({ credential: { rpId: "localhost" } });

    await expect(
      createCredential({
        rpId: "127.0.0.1",
        rpName: "IP loopback",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: "http://127.0.0.1:3000",
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("Invalid WebAuthn origin");
  });

  it("requires a distinct trustworthy top origin for cross-origin ceremonies", async () => {
    const input = {
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "test",
      challenge: randomChallenge(),
      origin: ORIGIN,
      crossOrigin: true,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    };

    await expect(createCredential(input)).rejects.toThrow(
      "Cross-origin ceremonies require a distinct topOrigin",
    );
    await expect(createCredential({ ...input, topOrigin: ORIGIN })).rejects.toThrow(
      "Cross-origin ceremonies require a distinct topOrigin",
    );
    await expect(createCredential({ ...input, topOrigin: "http://attacker.example" })).rejects.toThrow(
      "Invalid WebAuthn origin",
    );
  });

  it("rejects an RP ID outside the caller origin before creating a credential", async () => {
    await expect(
      createCredential({
        rpId: "attacker.example",
        rpName: "Attacker",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: ORIGIN,
        algorithms: [-7],
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("RP ID is not valid for origin");
  });

  it("does not satisfy required user verification without verification evidence", async () => {
    await expect(
      createCredential({
        rpId: RP_ID,
        rpName: "Example",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: ORIGIN,
        algorithms: [-7],
        userVerification: "required",
        ceremony: {
          ...VERIFIED_SYNCED_CEREMONY,
          userVerified: false,
        },
      }),
    ).rejects.toThrow("User verification is required");
  });

  it("rejects a ceremony without explicit security facts", async () => {
    const incompleteInput = {
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "test",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
    } as CreateCredentialInput;

    await expect(createCredential(incompleteInput)).rejects.toThrow(
      "Explicit ceremony facts are required",
    );
  });

  it("rejects unsupported algorithms", async () => {
    await expect(
      createCredential({
        rpId: RP_ID,
        rpName: "Example",
        userId: new Uint8Array([1]),
        userName: "test",
        challenge: randomChallenge(),
        origin: ORIGIN,
        algorithms: [-8, -257], // EdDSA, RS256 -- not supported
        ceremony: VERIFIED_SYNCED_CEREMONY,
      }),
    ).rejects.toThrow("No supported algorithm");
  });
});

describe("getAssertion edge cases", () => {
  it("rejects an invalid registrable-domain context before importing signing material", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "test",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    await expect(getAssertion({
      rpId: "com",
      challenge: randomChallenge(),
      origin: "https://shop.example.com",
      credential: {
        ...createResult.credential,
        rpId: "com",
        privateKeyPkcs8: new Uint8Array([0]),
      },
      ceremony: VERIFIED_SYNCED_CEREMONY,
    })).rejects.toThrow("RP ID is not a registrable domain suffix");
  });

  it("rejects an RP mismatch before attempting to import signing material", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "test",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    await expect(getAssertion({
      rpId: "other.example",
      challenge: randomChallenge(),
      origin: "https://other.example",
      credential: {
        ...createResult.credential,
        privateKeyPkcs8: new Uint8Array([0]),
      },
      ceremony: VERIFIED_SYNCED_CEREMONY,
    })).rejects.toThrow("Credential RP ID does not match request");
  });

  it("rejects an impossible backup-state claim", async () => {
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([1]),
      userName: "test",
      challenge: randomChallenge(),
      origin: ORIGIN,
      algorithms: [-7],
      ceremony: VERIFIED_SYNCED_CEREMONY,
    });

    await expect(getAssertion({
      rpId: RP_ID,
      challenge: randomChallenge(),
      origin: ORIGIN,
      credential: createResult.credential,
      ceremony: {
        ...VERIFIED_SYNCED_CEREMONY,
        backupEligible: false,
        backupState: true,
      },
    })).rejects.toThrow("backupState requires backupEligible");
  });
});

describe("P1363 to DER unit tests", () => {
  it("handles values with leading zeros", () => {
    // r = 0x00FF..., s = 0x0001...
    const p1363 = new Uint8Array(64);
    p1363[0] = 0x00;
    p1363[1] = 0xff;
    p1363[32] = 0x00;
    p1363[33] = 0x01;

    const der = p1363ToDer(p1363);
    expect(der[0]).toBe(0x30); // SEQUENCE
    expect(der[2]).toBe(0x02); // INTEGER
  });

  it("adds leading zero when high bit set", () => {
    const p1363 = new Uint8Array(64);
    p1363[0] = 0x80; // high bit set -> needs padding
    p1363[32] = 0x7f; // high bit not set -> no padding

    const der = p1363ToDer(p1363);

    // r: high bit set, so DER INTEGER should have leading 0x00
    expect(der[2]).toBe(0x02); // INTEGER tag
    const rLen = der[3];
    expect(der[4]).toBe(0x00); // leading zero pad
    expect(der[5]).toBe(0x80); // original value

    // s: high bit not set, no leading zero
    const sOffset = 4 + rLen;
    expect(der[sOffset]).toBe(0x02); // INTEGER tag
    expect(der[sOffset + 2]).toBe(0x7f); // original value, no pad
  });
});
