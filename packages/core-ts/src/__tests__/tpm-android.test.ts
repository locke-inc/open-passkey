import { describe, it, expect } from "vitest";
import {
  createHash,
  createSign,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { verifyTpmAttestation } from "../tpm.js";
import { verifyAndroidKeyAttestation } from "../android-key.js";
import { WebAuthnError } from "../errors.js";

// Synthetic fixtures for the TPM (§8.3) and android-key (§8.4) attestation
// formats. Certificates are hand-built self-signed P-256 certs (DER-encoded
// in this file — Node has no stdlib cert-creation API), and certInfo/pubArea
// are hand-built TPM structures. No network, no fixtures from disk.

// ---------- minimal DER builder ----------

function derLength(n: number): Buffer {
  if (n < 128) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLength(content.length), content]);
}

const derSeq = (...parts: Buffer[]): Buffer =>
  tlv(0x30, Buffer.concat(parts));
const derSet = (...parts: Buffer[]): Buffer =>
  tlv(0x31, Buffer.concat(parts));

function derInt(n: number): Buffer {
  if (n === 0) return tlv(0x02, Buffer.from([0x00]));
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return tlv(0x02, Buffer.from(bytes));
}

function derEnum(n: number): Buffer {
  return tlv(0x0a, Buffer.from([n & 0xff]));
}

function derOctets(b: Buffer): Buffer {
  return tlv(0x04, b);
}

function derUtf8(s: string): Buffer {
  return tlv(0x0c, Buffer.from(s, "utf8"));
}

function derUtc(s: string): Buffer {
  return tlv(0x17, Buffer.from(s, "ascii"));
}

function derOid(first: number, second: number, ...rest: number[]): Buffer {
  const out: number[] = [first * 40 + second];
  for (const arc of rest) {
    const stack: number[] = [arc & 0x7f];
    let v = Math.floor(arc / 128);
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v = Math.floor(v / 128);
    }
    out.push(...stack);
  }
  return tlv(0x06, Buffer.from(out));
}

// Minimal self-signed P-256 cert: TBSCertificate with v3 version, CN=Test,
// and optional extensions; ECDSA-with-SHA256 signature by signKey.
function selfSignedCert(
  spkiDer: Buffer,
  signKey: KeyObject,
  extensions: Buffer[],
): Buffer {
  const sigAlg = derSeq(derOid(1, 2, 840, 10045, 4, 3, 2));
  const name = derSeq(
    derSet(derSeq(derOid(2, 5, 4, 3), derUtf8("Test"))),
  );
  const validity = derSeq(derUtc("260101000000Z"), derUtc("270101000000Z"));
  let tbsInner = Buffer.concat([
    tlv(0xa0, derInt(2)),
    derInt(1),
    sigAlg,
    name,
    validity,
    name,
    spkiDer,
  ]);
  if (extensions.length > 0) {
    tbsInner = Buffer.concat([tbsInner, tlv(0xa3, derSeq(...extensions))]);
  }
  const tbs = derSeq(tbsInner);
  const sig = createSign("SHA256").update(tbs).sign(signKey);
  return derSeq(tbs, sigAlg, tlv(0x03, Buffer.concat([Buffer.from([0x00]), sig])));
}

// ---------- shared helpers ----------

function sha256b(data: Uint8Array): Buffer {
  return createHash("sha256").update(data).digest();
}

function ecCoords(pub: KeyObject): { x: Buffer; y: Buffer } {
  const jwk = pub.export({ format: "jwk" });
  if (typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new Error("expected EC JWK coordinates");
  }
  return {
    x: Buffer.from(jwk.x, "base64url"),
    y: Buffer.from(jwk.y, "base64url"),
  };
}

function fakeAuthData(): Buffer {
  const rpIdHash = sha256b(Buffer.from("example.com"));
  const rest = Buffer.alloc(5);
  rest[0] = 0x41; // UP + AT
  rest.writeUInt32BE(1, 1);
  return Buffer.concat([rpIdHash, rest]);
}

// Hand-encoded COSE ES256 key (plain CBOR map — cbor-x encodes JS Maps with
// tag 259, which decode() restores as Map instead of an object).
function coseES256(x: Buffer, y: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
    x,
    Buffer.from([0x22, 0x58, 0x20]),
    y,
  ]);
}

function expectCode(fn: () => void, code: string, msgPart?: string): void {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(WebAuthnError);
    expect((err as WebAuthnError).code).toBe(code);
    if (msgPart !== undefined) {
      expect((err as Error).message).toContain(msgPart);
    }
    return;
  }
  expect.fail(`expected error ${code}`);
}

// ---------- TPM fixtures ----------

function tpm2b(content: Buffer): Buffer {
  const len = Buffer.alloc(2);
  len.writeUInt16BE(content.length);
  return Buffer.concat([len, content]);
}

// TPM2B_PUBLIC holding an ECC P-256 key with the given nameAlg.
function buildPubArea(x: Buffer, y: Buffer, nameAlg = 0x000b): Buffer {
  const head = Buffer.alloc(2 + 2 + 4);
  head.writeUInt16BE(0x0023, 0); // TPM_ALG_ECC
  head.writeUInt16BE(nameAlg, 2);
  head.writeUInt32BE(0, 4); // objectAttributes
  return Buffer.concat([
    head,
    tpm2b(Buffer.alloc(0)), // authPolicy
    Buffer.alloc(8), // symmetric, scheme, curveID, kdf
    tpm2b(x),
    tpm2b(y),
  ]);
}

// TPMS_ATTEST (certify) with caller-supplied extraData/name.
function buildCertInfo(opts: {
  magic?: number;
  type?: number;
  extraData: Buffer;
  name: Buffer;
}): Buffer {
  const magic = Buffer.alloc(4);
  magic.writeUInt32BE(opts.magic ?? 0xff544347);
  const type = Buffer.alloc(2);
  type.writeUInt16BE(opts.type ?? 0x8017);
  return Buffer.concat([
    magic,
    type,
    tpm2b(Buffer.alloc(0)), // qualifiedSigner
    tpm2b(opts.extraData),
    Buffer.alloc(17), // clockInfo
    Buffer.alloc(8), // firmwareVersion
    tpm2b(opts.name),
    tpm2b(Buffer.alloc(0)), // qualifiedName
  ]);
}

interface TpmFixture {
  stmt: {
    ver: unknown;
    alg: number;
    sig: Uint8Array;
    x5c: Uint8Array[];
    certInfo: Uint8Array;
    pubArea: Uint8Array;
  };
  authData: Uint8Array;
  clientDataHash: Uint8Array;
  cose: Uint8Array;
  certInfo: Buffer;
  extraData: Buffer;
  name: Buffer;
}

function buildTpmFixture(): TpmFixture {
  const cred = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const aik = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = ecCoords(cred.publicKey);
  const authData = fakeAuthData();
  const clientDataJSON = Buffer.from(
    '{"type":"webauthn.create","challenge":"c","origin":"https://example.com"}',
  );
  const clientDataHash = sha256b(clientDataJSON);
  const pubArea = buildPubArea(x, y);
  // TPM name computed independently of computeTpmName: alg id || sha256(pubArea).
  const nameAlgId = Buffer.alloc(2);
  nameAlgId.writeUInt16BE(0x000b);
  const name = Buffer.concat([nameAlgId, sha256b(pubArea)]);
  // extraData is the nameAlg hash of attToBeSigned (the fixed behavior).
  const extraData = sha256b(Buffer.concat([authData, clientDataHash]));
  const certInfo = buildCertInfo({ extraData, name });
  const aikSpki = aik.publicKey.export({ format: "der", type: "spki" });
  const aikCert = selfSignedCert(Buffer.from(aikSpki), aik.privateKey, []);
  const sig = createSign("SHA256").update(certInfo).sign(aik.privateKey);
  return {
    stmt: {
      ver: "2.0",
      alg: -7,
      sig: new Uint8Array(sig),
      x5c: [new Uint8Array(aikCert)],
      certInfo: new Uint8Array(certInfo),
      pubArea: new Uint8Array(pubArea),
    },
    authData: new Uint8Array(authData),
    clientDataHash: new Uint8Array(clientDataHash),
    cose: new Uint8Array(coseES256(x, y)),
    certInfo,
    extraData,
    name,
  };
}

describe("TPM attestation", () => {
  it("accepts a valid statement with hashed extraData", () => {
    const f = buildTpmFixture();
    expect(() =>
      verifyTpmAttestation(f.stmt, f.authData, f.clientDataHash, f.cose),
    ).not.toThrow();
  });

  it("rejects a tampered signature", () => {
    const f = buildTpmFixture();
    const badSig = Buffer.from(f.stmt.sig);
    badSig[badSig.length - 1] ^= 0x01;
    expectCode(
      () =>
        verifyTpmAttestation(
          { ...f.stmt, sig: new Uint8Array(badSig) },
          f.authData,
          f.clientDataHash,
          f.cose,
        ),
      "signature_invalid",
    );
  });

  it("rejects bad magic", () => {
    const f = buildTpmFixture();
    const badCertInfo = buildCertInfo({
      magic: 0x00000000,
      extraData: f.extraData,
      name: f.name,
    });
    expectCode(
      () =>
        verifyTpmAttestation(
          { ...f.stmt, certInfo: new Uint8Array(badCertInfo) },
          f.authData,
          f.clientDataHash,
          f.cose,
        ),
      "invalid_attestation_statement",
      "bad magic",
    );
  });

  it("rejects name mismatch", () => {
    const f = buildTpmFixture();
    const badName = Buffer.from(f.name);
    badName[badName.length - 1] ^= 0x01;
    const badCertInfo = buildCertInfo({ extraData: f.extraData, name: badName });
    expectCode(
      () =>
        verifyTpmAttestation(
          { ...f.stmt, certInfo: new Uint8Array(badCertInfo) },
          f.authData,
          f.clientDataHash,
          f.cose,
        ),
      "invalid_attestation_statement",
      "name mismatch",
    );
  });

  it("rejects extraData mismatch", () => {
    const f = buildTpmFixture();
    const badExtra = sha256b(Buffer.from("wrong"));
    const badCertInfo = buildCertInfo({ extraData: badExtra, name: f.name });
    expectCode(
      () =>
        verifyTpmAttestation(
          { ...f.stmt, certInfo: new Uint8Array(badCertInfo) },
          f.authData,
          f.clientDataHash,
          f.cose,
        ),
      "invalid_attestation_statement",
      "extraData mismatch",
    );
  });

  it("rejects raw attToBeSigned as extraData (must be hashed)", () => {
    // Guards the original bug: extraData holding attToBeSigned verbatim.
    const f = buildTpmFixture();
    const raw = Buffer.concat([
      Buffer.from(f.authData),
      Buffer.from(f.clientDataHash),
    ]);
    const badCertInfo = buildCertInfo({ extraData: raw, name: f.name });
    expectCode(
      () =>
        verifyTpmAttestation(
          { ...f.stmt, certInfo: new Uint8Array(badCertInfo) },
          f.authData,
          f.clientDataHash,
          f.cose,
        ),
      "invalid_attestation_statement",
      "extraData mismatch",
    );
  });
});

// ---------- android-key fixtures ----------

// KeyDescription ::= SEQUENCE { attestationVersion INTEGER,
//   attestationSecurityLevel ENUMERATED, keymasterVersion INTEGER,
//   keymasterSecurityLevel ENUMERATED, attestationChallenge OCTET STRING,
//   uniqueId OCTET STRING, softwareEnforced AuthorizationList,
//   teeEnforced AuthorizationList }
function keyDescription(securityLevel: number, challenge: Buffer): Buffer {
  return derSeq(
    derInt(3), // attestationVersion
    derEnum(securityLevel), // attestationSecurityLevel
    derInt(4), // keymasterVersion
    derEnum(1), // keymasterSecurityLevel (TEE)
    derOctets(challenge), // attestationChallenge
    derOctets(Buffer.alloc(0)), // uniqueId
    derSeq(), // softwareEnforced
    derSeq(), // teeEnforced
  );
}

function androidExtension(securityLevel: number, challenge: Buffer): Buffer {
  return derSeq(
    derOid(1, 3, 6, 1, 4, 1, 11129, 2, 1, 17),
    derOctets(keyDescription(securityLevel, challenge)),
  );
}

interface AndroidFixture {
  stmt: { alg: number; sig: Uint8Array; x5c: Uint8Array[] };
  authData: Uint8Array;
  clientDataHash: Uint8Array;
}

function buildAndroidFixture(
  securityLevel: number,
  challenge?: Buffer,
): AndroidFixture {
  const leaf = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const authData = fakeAuthData();
  const clientDataJSON = Buffer.from(
    '{"type":"webauthn.create","challenge":"c","origin":"https://example.com"}',
  );
  const clientDataHash = sha256b(clientDataJSON);
  const leafSpki = leaf.publicKey.export({ format: "der", type: "spki" });
  const leafCert = selfSignedCert(Buffer.from(leafSpki), leaf.privateKey, [
    androidExtension(securityLevel, challenge ?? clientDataHash),
  ]);
  const sig = createSign("SHA256")
    .update(Buffer.concat([authData, clientDataHash]))
    .sign(leaf.privateKey);
  return {
    stmt: {
      alg: -7,
      sig: new Uint8Array(sig),
      x5c: [new Uint8Array(leafCert)],
    },
    authData: new Uint8Array(authData),
    clientDataHash: new Uint8Array(clientDataHash),
  };
}

describe("android-key attestation", () => {
  it("accepts a valid TEE statement", () => {
    const f = buildAndroidFixture(1);
    expect(() =>
      verifyAndroidKeyAttestation(f.stmt, f.authData, f.clientDataHash),
    ).not.toThrow();
  });

  it("accepts a valid StrongBox statement", () => {
    const f = buildAndroidFixture(2);
    expect(() =>
      verifyAndroidKeyAttestation(f.stmt, f.authData, f.clientDataHash),
    ).not.toThrow();
  });

  it("rejects a tampered signature", () => {
    const f = buildAndroidFixture(1);
    const badSig = Buffer.from(f.stmt.sig);
    badSig[0] ^= 0x01;
    expectCode(
      () =>
        verifyAndroidKeyAttestation(
          { ...f.stmt, sig: new Uint8Array(badSig) },
          f.authData,
          f.clientDataHash,
        ),
      "signature_invalid",
    );
  });

  it("rejects software-only attestation", () => {
    const f = buildAndroidFixture(0);
    expectCode(
      () => verifyAndroidKeyAttestation(f.stmt, f.authData, f.clientDataHash),
      "invalid_attestation_statement",
      "software-only",
    );
  });

  it("rejects attestationChallenge mismatch", () => {
    const f = buildAndroidFixture(1, sha256b(Buffer.from("other")));
    expectCode(
      () => verifyAndroidKeyAttestation(f.stmt, f.authData, f.clientDataHash),
      "invalid_attestation_statement",
      "attestationChallenge mismatch",
    );
  });
});
