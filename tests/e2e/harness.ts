import { createCredential, getAssertion } from "@open-passkey/authenticator";
import { expect } from "vitest";

function base64urlDecode(str: string): Uint8Array {
  let padded = str.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function post(baseUrl: string, path: string, body: unknown): Promise<Response> {
  return fetch(`${baseUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * Drives a full registration + authentication ceremony against a live server.
 * Uses authenticator-ts as a headless software authenticator.
 */
export async function runFullCeremony(baseUrl: string, origin: string) {
  const userId = `e2e-test-${Date.now()}`;
  const username = `testuser-${Date.now()}`;

  // --- Registration ---

  // Step 1: Begin registration
  const regBeginRes = await post(baseUrl, "/passkey/register/begin", {
    userId,
    username,
  });
  expect(regBeginRes.status, "register/begin should return 200").toBe(200);
  const regOptions = await regBeginRes.json();

  expect(regOptions.challenge).toBeDefined();
  expect(regOptions.rp.id).toBeDefined();
  expect(regOptions.user.id).toBeDefined();
  expect(regOptions.pubKeyCredParams.length).toBeGreaterThan(0);

  // Step 2: Create credential with software authenticator
  const algorithms = regOptions.pubKeyCredParams
    .map((p: { alg: number }) => p.alg)
    .filter((alg: number) => alg === -7); // Use ES256 for E2E (universally supported)

  const createResult = await createCredential({
    rpId: regOptions.rp.id,
    rpName: regOptions.rp.name,
    userId: base64urlDecode(regOptions.user.id),
    userName: username,
    challenge: base64urlDecode(regOptions.challenge),
    origin,
    algorithms,
  });

  // Step 3: Finish registration
  const regFinishRes = await post(baseUrl, "/passkey/register/finish", {
    userId,
    credential: {
      id: createResult.credentialId,
      rawId: createResult.credentialId,
      type: "public-key",
      response: {
        clientDataJSON: createResult.response.clientDataJSON,
        attestationObject: createResult.response.attestationObject,
      },
    },
  });
  expect(regFinishRes.status, "register/finish should return 200").toBe(200);
  const regFinishData = await regFinishRes.json();
  expect(regFinishData.registered).toBe(true);
  expect(regFinishData.credentialId).toBeDefined();

  // --- Authentication ---

  // Step 4: Begin authentication
  const authBeginRes = await post(baseUrl, "/passkey/login/begin", {
    userId,
  });
  expect(authBeginRes.status, "login/begin should return 200").toBe(200);
  const authOptions = await authBeginRes.json();

  expect(authOptions.challenge).toBeDefined();
  expect(authOptions.rpId).toBeDefined();

  // Step 5: Create assertion with software authenticator
  const assertionResult = await getAssertion({
    rpId: authOptions.rpId,
    challenge: base64urlDecode(authOptions.challenge),
    origin,
    credential: createResult.credential,
  });

  // Step 6: Finish authentication
  const authFinishRes = await post(baseUrl, "/passkey/login/finish", {
    userId,
    credential: {
      id: createResult.credentialId,
      rawId: createResult.credentialId,
      type: "public-key",
      response: {
        clientDataJSON: assertionResult.response.clientDataJSON,
        authenticatorData: assertionResult.response.authenticatorData,
        signature: assertionResult.response.signature,
        userHandle: assertionResult.response.userHandle,
      },
    },
  });
  expect(authFinishRes.status, "login/finish should return 200").toBe(200);
  const authFinishData = await authFinishRes.json();
  expect(authFinishData.authenticated).toBe(true);
  expect(authFinishData.userId).toBe(userId);

  return { userId, credentialId: regFinishData.credentialId };
}

/**
 * Tests that an invalid credential is rejected during authentication.
 */
export async function runInvalidAuthTest(baseUrl: string, origin: string) {
  const userId = `e2e-invalid-${Date.now()}`;
  const username = `invaliduser-${Date.now()}`;

  // Register a valid credential first
  const regBeginRes = await post(baseUrl, "/passkey/register/begin", { userId, username });
  const regOptions = await regBeginRes.json();

  const algorithms = regOptions.pubKeyCredParams
    .map((p: { alg: number }) => p.alg)
    .filter((alg: number) => alg === -7);

  const createResult = await createCredential({
    rpId: regOptions.rp.id,
    rpName: regOptions.rp.name,
    userId: base64urlDecode(regOptions.user.id),
    userName: username,
    challenge: base64urlDecode(regOptions.challenge),
    origin,
    algorithms,
  });

  await post(baseUrl, "/passkey/register/finish", {
    userId,
    credential: {
      id: createResult.credentialId,
      rawId: createResult.credentialId,
      type: "public-key",
      response: createResult.response,
    },
  });

  // Begin authentication
  const authBeginRes = await post(baseUrl, "/passkey/login/begin", { userId });
  const authOptions = await authBeginRes.json();

  // Create a valid assertion
  const assertionResult = await getAssertion({
    rpId: authOptions.rpId,
    challenge: base64urlDecode(authOptions.challenge),
    origin,
    credential: createResult.credential,
  });

  // Tamper with the signature (flip a byte)
  const tamperedSig = base64urlDecode(assertionResult.response.signature);
  tamperedSig[tamperedSig.length - 1] ^= 0xff;

  const authFinishRes = await post(baseUrl, "/passkey/login/finish", {
    userId,
    credential: {
      id: createResult.credentialId,
      rawId: createResult.credentialId,
      type: "public-key",
      response: {
        ...assertionResult.response,
        signature: base64urlEncode(tamperedSig),
      },
    },
  });

  expect(
    authFinishRes.status >= 400,
    `tampered signature should be rejected (got ${authFinishRes.status})`,
  ).toBe(true);
}
