import { describe, expect, it } from "vitest";
import { createCredential, getAssertion } from "@open-passkey/authenticator";
import type { CeremonyFacts, StoredCredential } from "@open-passkey/authenticator";
import {
  CeremonyAbortedError,
  CeremonyTimeoutError,
  ReferenceRelyingParty,
  UnsupportedExtensionError,
  bytes,
} from "./reference-rp.js";

const PRESENT: CeremonyFacts = {
  userPresent: true,
  userVerified: false,
  backupEligible: true,
  backupState: true,
};

const VERIFIED: CeremonyFacts = { ...PRESENT, userVerified: true };

async function register(
  rp: ReferenceRelyingParty,
  userId: string,
  userName: string,
): Promise<StoredCredential> {
  const options = rp.beginRegistration({ userId, userName });
  const created = await createCredential({
    rpId: options.rp.id,
    rpName: options.rp.name,
    userId: options.user.id,
    userName: options.user.name,
    challenge: options.challenge,
    origin: rp.origin,
    algorithms: options.algorithms,
    ceremony: VERIFIED,
  });
  rp.finishRegistration(options.ceremonyId, created.credentialId, created.response);
  return created.credential;
}

describe("local external-passkey relying party", () => {
  it("registers and authenticates an explicit allowCredentials match cryptographically", async () => {
    const rp = new ReferenceRelyingParty();
    const credential = await register(rp, "ada", "ada@example.test");
    const options = rp.beginAuthentication({
      allowCredentials: [credential.credentialId],
      userVerification: "required",
    });

    expect(options.candidates.map((candidate) => candidate.userName)).toEqual([
      "ada@example.test",
    ]);

    const assertion = await getAssertion({
      rpId: rp.rpId,
      challenge: options.challenge,
      origin: rp.origin,
      credential,
      userVerification: options.userVerification,
      ceremony: VERIFIED,
    });

    const result = rp.finishAuthentication(
      options.ceremonyId,
      credential.credentialId,
      assertion.response,
    );
    expect(result).toMatchObject({ userId: "ada", flags: 0x1d, signCount: 0 });
  });

  it.each(["required", "preferred", "discouraged"] as const)(
    "enforces truthful UV for userVerification=%s",
    async (userVerification) => {
      const rp = new ReferenceRelyingParty();
      const credential = await register(rp, "uv-user", "uv@example.test");
      const options = rp.beginAuthentication({ userId: "uv-user", userVerification });
      const get = () => getAssertion({
        rpId: rp.rpId,
        challenge: options.challenge,
        origin: rp.origin,
        credential,
        userVerification,
        ceremony: PRESENT,
      });

      if (userVerification === "required") {
        await expect(get()).rejects.toThrow("User verification is required");
      } else {
        const assertion = await get();
        const result = rp.finishAuthentication(
          options.ceremonyId,
          credential.credentialId,
          assertion.response,
        );
        expect(result.flags & 0x04).toBe(0);
      }
    },
  );

  it("supports discoverable and conditional requests and requires explicit selection for multiple identities", async () => {
    const rp = new ReferenceRelyingParty();
    const ada = await register(rp, "ada", "ada@example.test");
    const grace = await register(rp, "grace", "grace@example.test");

    const discoverable = rp.beginAuthentication({ mediation: "optional" });
    expect(discoverable.candidates.map((candidate) => candidate.userName).sort()).toEqual([
      "ada@example.test",
      "grace@example.test",
    ]);
    expect(() => rp.selectCredential(discoverable.ceremonyId)).toThrow(
      "credential_selection_required",
    );
    expect(
      rp.selectCredential(discoverable.ceremonyId, grace.credentialId).userId,
    ).toBe("grace");

    const conditional = rp.beginAuthentication({ mediation: "conditional" });
    expect(conditional.mediation).toBe("conditional");
    expect(rp.selectCredential(conditional.ceremonyId, ada.credentialId).userId).toBe("ada");
  });

  it("accepts a nullable userHandle for an explicitly identified account but not discoverable login", async () => {
    const rp = new ReferenceRelyingParty();
    const credential = await register(rp, "nullable", "nullable@example.test");

    const explicit = rp.beginAuthentication({ userId: "nullable" });
    const assertion = await getAssertion({
      rpId: rp.rpId,
      challenge: explicit.challenge,
      origin: rp.origin,
      credential: { ...credential, userId: null },
      ceremony: VERIFIED,
    });
    expect(assertion.response.userHandle).toBeNull();
    expect(
      rp.finishAuthentication(explicit.ceremonyId, credential.credentialId, assertion.response)
        .userId,
    ).toBe("nullable");

    const discoverable = rp.beginAuthentication();
    const discoverableAssertion = await getAssertion({
      rpId: rp.rpId,
      challenge: discoverable.challenge,
      origin: rp.origin,
      credential: { ...credential, userId: null },
      ceremony: VERIFIED,
    });
    expect(() =>
      rp.finishAuthentication(
        discoverable.ceremonyId,
        credential.credentialId,
        discoverableAssertion.response,
      ),
    ).toThrow("user_handle_required");
  });

  it("ignores optional PRF but rejects a required unsupported extension before signing", async () => {
    const rp = new ReferenceRelyingParty();
    const credential = await register(rp, "extensions", "extensions@example.test");

    const optional = rp.beginAuthentication({
      userId: "extensions",
      extensions: { prf: { required: false }, largeBlob: { required: false } },
    });
    expect(optional.extensions).toEqual({});
    expect(optional.unsupportedExtensions.sort()).toEqual(["largeBlob", "prf"]);

    expect(() =>
      rp.beginAuthentication({
        allowCredentials: [credential.credentialId],
        extensions: { prf: { required: true } },
      }),
    ).toThrow(UnsupportedExtensionError);
  });

  it("settles abort and timeout deterministically without invoking the authenticator", async () => {
    let now = 1_000;
    const rp = new ReferenceRelyingParty({ now: () => now });
    await register(rp, "settlement", "settlement@example.test");

    const controller = new AbortController();
    const aborted = rp.beginAuthentication({ userId: "settlement", signal: controller.signal });
    controller.abort();
    expect(() => rp.selectCredential(aborted.ceremonyId)).toThrow(CeremonyAbortedError);

    const timedOut = rp.beginAuthentication({ userId: "settlement", timeoutMs: 50 });
    now += 51;
    expect(() => rp.selectCredential(timedOut.ceremonyId)).toThrow(CeremonyTimeoutError);
  });

  it("isolates concurrent ceremonies and rejects challenge cross-talk", async () => {
    const rp = new ReferenceRelyingParty();
    const credential = await register(rp, "concurrent", "concurrent@example.test");
    const first = rp.beginAuthentication({ userId: "concurrent" });
    const second = rp.beginAuthentication({ userId: "concurrent" });
    expect(bytes(first.challenge)).not.toBe(bytes(second.challenge));

    const firstAssertion = await getAssertion({
      rpId: rp.rpId,
      challenge: first.challenge,
      origin: rp.origin,
      credential,
      ceremony: VERIFIED,
    });
    expect(() =>
      rp.finishAuthentication(
        second.ceremonyId,
        credential.credentialId,
        firstAssertion.response,
      ),
    ).toThrow("challenge_mismatch");

    expect(
      rp.finishAuthentication(
        first.ceremonyId,
        credential.credentialId,
        firstAssertion.response,
      ).userId,
    ).toBe("concurrent");
  });

  it("rejects a tampered signature through independent core verification", async () => {
    const rp = new ReferenceRelyingParty();
    const credential = await register(rp, "tamper", "tamper@example.test");
    const options = rp.beginAuthentication({ userId: "tamper" });
    const assertion = await getAssertion({
      rpId: rp.rpId,
      challenge: options.challenge,
      origin: rp.origin,
      credential,
      ceremony: VERIFIED,
    });
    const signature = Uint8Array.from(Buffer.from(assertion.response.signature, "base64url"));
    signature[signature.length - 1] ^= 0xff;

    expect(() =>
      rp.finishAuthentication(options.ceremonyId, credential.credentialId, {
        ...assertion.response,
        signature: Buffer.from(signature).toString("base64url"),
      }),
    ).toThrow("signature_invalid");
  });
});
