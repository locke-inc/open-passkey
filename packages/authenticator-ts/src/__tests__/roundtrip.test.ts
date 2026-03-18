import { describe, it, expect } from "vitest";
import { createCredential, getAssertion, p1363ToDer } from "../index.js";
import { verifyRegistration, verifyAuthentication } from "../../../core-ts/src/index.js";

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const RP_ID = "example.com";
const ORIGIN = "https://example.com";

function randomChallenge(): Uint8Array {
  const buf = new Uint8Array(32);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

describe("Registration round-trip", () => {
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
    });

    // Now create an assertion
    const authChallenge = randomChallenge();
    const assertionResult = await getAssertion({
      rpId: RP_ID,
      challenge: authChallenge,
      origin: ORIGIN,
      credential: createResult.credential,
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

    expect(authResult.signCount).toBe(1);
    expect(authResult.backupEligible).toBe(true);
    expect(authResult.backupState).toBe(true);
    expect(assertionResult.updatedCredential.signCount).toBe(1);
  });

  it("increments sign count across multiple assertions", async () => {
    const regChallenge = randomChallenge();
    const createResult = await createCredential({
      rpId: RP_ID,
      rpName: "Example",
      userId: new Uint8Array([9, 10]),
      userName: "testuser",
      challenge: regChallenge,
      origin: ORIGIN,
      algorithms: [-7],
    });

    let credential = createResult.credential;

    for (let i = 1; i <= 3; i++) {
      const challenge = randomChallenge();
      const assertion = await getAssertion({
        rpId: RP_ID,
        challenge,
        origin: ORIGIN,
        credential,
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

      expect(authResult.signCount).toBe(i);
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
    });

    const authChallenge = randomChallenge();
    const assertion = await getAssertion({
      rpId: RP_ID,
      challenge: authChallenge,
      origin: ORIGIN,
      credential: createResult.credential,
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
      }),
    ).rejects.toThrow("No supported algorithm");
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
