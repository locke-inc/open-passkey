/**
 * Convert an ECDSA P1363 signature (r || s, each 32 bytes for P-256) to DER format.
 *
 * DER encoding:
 *   SEQUENCE { INTEGER r, INTEGER s }
 *   - Each integer gets a leading 0x00 if its high bit is set (to avoid being interpreted as negative).
 *   - Leading zero bytes are stripped (except one if needed for sign).
 */
export function p1363ToDer(p1363: Uint8Array): Uint8Array {
  const half = p1363.length / 2;
  const r = p1363.slice(0, half);
  const s = p1363.slice(half);
  const rDer = integerToDer(r);
  const sDer = integerToDer(s);
  // SEQUENCE tag = 0x30, length, then r and s
  const seqLen = rDer.length + sDer.length;
  const result = new Uint8Array(2 + seqLen);
  result[0] = 0x30;
  result[1] = seqLen;
  result.set(rDer, 2);
  result.set(sDer, 2 + rDer.length);
  return result;
}

function integerToDer(value: Uint8Array): Uint8Array {
  // Strip leading zeros
  let start = 0;
  while (start < value.length - 1 && value[start] === 0) {
    start++;
  }
  const stripped = value.slice(start);

  // Add leading 0x00 if high bit set
  const needsPad = stripped[0] & 0x80;
  const len = stripped.length + (needsPad ? 1 : 0);
  const result = new Uint8Array(2 + len);
  result[0] = 0x02; // INTEGER tag
  result[1] = len;
  if (needsPad) {
    result[2] = 0x00;
    result.set(stripped, 3);
  } else {
    result.set(stripped, 2);
  }
  return result;
}
