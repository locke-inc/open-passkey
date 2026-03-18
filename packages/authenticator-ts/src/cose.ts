import * as cborg from "cborg";

const COSE_KTY = 1;
const COSE_ALG = 3;
const COSE_CRV = -1;
const COSE_X = -2;
const COSE_Y = -3;

const KTY_EC2 = 2;
const CRV_P256 = 1;

export const ALG_ES256 = -7;

export function encodeES256PublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  // COSE_Key for EC2 P-256: {1:2, 3:-7, -1:1, -2:x, -3:y}
  // cborg encodes Map objects with proper integer keys
  const map = new Map<number, number | Uint8Array>();
  map.set(COSE_KTY, KTY_EC2);
  map.set(COSE_ALG, ALG_ES256);
  map.set(COSE_CRV, CRV_P256);
  map.set(COSE_X, x);
  map.set(COSE_Y, y);
  return cborg.encode(map);
}
