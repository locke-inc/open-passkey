import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it, expect } from "vitest";
import { verifyRegistration } from "../registration.js";
import { verifyAuthentication } from "../authentication.js";
import { WebAuthnError } from "../errors.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsDir = resolve(__dirname, "../../../../spec/vectors");

interface Expected {
  success: boolean;
  error?: string;
  credentialId?: string;
  publicKeyCose?: string;
  signCount?: number;
  rpIdHash?: string;
}

interface TestVector {
  name: string;
  description: string;
  input: Record<string, any>;
  expected: Expected;
}

interface VectorFile {
  description: string;
  vectors: TestVector[];
}

function loadVectors(filename: string): VectorFile {
  const path = resolve(vectorsDir, filename);
  return JSON.parse(readFileSync(path, "utf-8"));
}

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlDecode(input: string): Uint8Array {
  let padded = input.replace(/-/g, "+").replace(/_/g, "/");
  while (padded.length % 4 !== 0) padded += "=";
  return new Uint8Array(Buffer.from(padded, "base64"));
}

// --- Registration vectors ---

describe("Registration vectors", () => {
  const vf = loadVectors("registration.json");

  for (const vec of vf.vectors) {
    it(vec.name, () => {
      const { input, expected } = vec;
      const credential = input.credential;
      const response = credential.response;

      if (expected.success) {
        const result = verifyRegistration({
          rpId: input.rpId,
          expectedChallenge: input.expectedChallenge,
          expectedOrigin: input.expectedOrigin,
          clientDataJSON: response.clientDataJSON,
          attestationObject: response.attestationObject,
        });

        if (expected.credentialId) {
          expect(toBase64url(result.credentialId)).toBe(
            expected.credentialId,
          );
        }
        if (expected.publicKeyCose) {
          expect(toBase64url(result.publicKeyCose)).toBe(
            expected.publicKeyCose,
          );
        }
        if (expected.signCount !== undefined) {
          expect(result.signCount).toBe(expected.signCount);
        }
        if (expected.rpIdHash) {
          expect(toBase64url(result.rpIdHash)).toBe(expected.rpIdHash);
        }
      } else {
        try {
          verifyRegistration({
            rpId: input.rpId,
            expectedChallenge: input.expectedChallenge,
            expectedOrigin: input.expectedOrigin,
            clientDataJSON: response.clientDataJSON,
            attestationObject: response.attestationObject,
          });
          expect.fail(`Expected error "${expected.error}" but succeeded`);
        } catch (err) {
          if (err instanceof WebAuthnError) {
            expect(err.code).toBe(expected.error);
          } else {
            throw err;
          }
        }
      }
    });
  }
});

// --- Shared authentication vector runner ---

function runAuthenticationVectors(filename: string) {
  const vf = loadVectors(filename);

  for (const vec of vf.vectors) {
    it(vec.name, () => {
      const { input, expected } = vec;
      const credential = input.credential;
      const response = credential.response;

      const storedPubKey = base64urlDecode(input.storedPublicKeyCose);

      if (expected.success) {
        const result = verifyAuthentication({
          rpId: input.rpId,
          expectedChallenge: input.expectedChallenge,
          expectedOrigin: input.expectedOrigin,
          storedPublicKeyCose: storedPubKey,
          storedSignCount: input.storedSignCount,
          clientDataJSON: response.clientDataJSON,
          authenticatorData: response.authenticatorData,
          signature: response.signature,
        });

        if (expected.signCount !== undefined) {
          expect(result.signCount).toBe(expected.signCount);
        }
      } else {
        try {
          verifyAuthentication({
            rpId: input.rpId,
            expectedChallenge: input.expectedChallenge,
            expectedOrigin: input.expectedOrigin,
            storedPublicKeyCose: storedPubKey,
            storedSignCount: input.storedSignCount,
            clientDataJSON: response.clientDataJSON,
            authenticatorData: response.authenticatorData,
            signature: response.signature,
          });
          expect.fail(`Expected error "${expected.error}" but succeeded`);
        } catch (err) {
          if (err instanceof WebAuthnError) {
            expect(err.code).toBe(expected.error);
          } else {
            throw err;
          }
        }
      }
    });
  }
}

// --- Authentication vectors ---

describe("Authentication vectors", () => {
  runAuthenticationVectors("authentication.json");
});

// --- Hybrid ML-DSA-65-ES256 authentication vectors ---

describe("Hybrid authentication vectors", () => {
  runAuthenticationVectors("hybrid_authentication.json");
});
