import { describe, it, expect } from 'vitest';
import * as cborg from 'cborg';
import { createCredential, getAssertion } from '../index.js';
import { verifyRegistration, verifyAuthentication } from '../../../core-ts/src/index.js';
import { ceremonyFlags } from '../ceremony.js';

const facts = { userPresent: true, userVerified: false, backupEligible: true, backupState: true };
const input = { rpId: 'example.com', rpName: 'Example', userId: new Uint8Array([1]), userName: 'reader',
  challenge: new Uint8Array([1, 2, 3]), origin: 'https://example.com', algorithms: [-7], ceremony: facts };
const decode = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

describe('explicit ceremony facts', () => {
  it('rejects missing, partial, untyped, or absent presence facts', () => {
    for (const bad of [undefined, {}, { ...facts, userPresent: false }, { ...facts, userVerified: 'false' }]) {
      expect(() => ceremonyFlags(bad as any, 'preferred', false)).toThrow();
    }
  });
  it('never manufactures verification for an RP requirement', async () => {
    await expect(createCredential({ ...input, userVerification: 'required' })).rejects.toThrow('User verification required');
    const registered = await createCredential(input);
    await expect(getAssertion({ rpId: input.rpId, origin: input.origin, challenge: input.challenge,
      credential: registered.credential, ceremony: facts, userVerification: 'required' })).rejects.toThrow('User verification required');
  });
  it('encodes unverified registration and signed assertion without UV', async () => {
    const registered = await createCredential(input);
    const attestation = cborg.decode(decode(registered.response.attestationObject));
    expect(attestation.authData[32]).toBe(0x59);
    const assertion = await getAssertion({ rpId: input.rpId, origin: input.origin, challenge: input.challenge,
      credential: registered.credential, ceremony: facts });
    expect(decode(assertion.response.authenticatorData)[32]).toBe(0x19);
    const registration = verifyRegistration({ rpId: input.rpId, expectedOrigin: input.origin,
      expectedChallenge: Buffer.from(input.challenge).toString('base64url'),
      clientDataJSON: registered.response.clientDataJSON, attestationObject: registered.response.attestationObject,
      requireUserVerification: false });
    const verified = verifyAuthentication({ rpId: input.rpId, expectedOrigin: input.origin,
      expectedChallenge: Buffer.from(input.challenge).toString('base64url'),
      clientDataJSON: assertion.response.clientDataJSON, authenticatorData: assertion.response.authenticatorData,
      signature: assertion.response.signature, storedPublicKeyCose: registration.publicKeyCose,
      storedSignCount: 0, requireUserVerification: false });
    expect(verified.signCount).toBe(1);
  });
  it('uses supplied backup state and rejects impossible backup combinations', () => {
    expect(ceremonyFlags({ ...facts, backupEligible: false, backupState: false }, 'preferred', false)).toBe(1);
    expect(() => ceremonyFlags({ ...facts, backupEligible: false }, undefined, false)).toThrow('Invalid backup state');
  });
  it('rejects signing for another RP', async () => {
    const registered = await createCredential(input);
    await expect(getAssertion({ rpId: 'evil.com', origin: 'https://evil.com', challenge: input.challenge,
      credential: registered.credential, ceremony: facts })).rejects.toThrow('RP ID mismatch');
  });
});
