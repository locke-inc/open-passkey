import { base64urlDecode } from "./util.js";
import {
  TypeMismatchError,
  ChallengeMismatchError,
  OriginMismatchError,
  TokenBindingUnsupportedError,
} from "./errors.js";

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
  tokenBinding?: { status: string };
}

export function verifyClientData(
  clientDataJSONB64: string,
  expectedType: string,
  expectedChallenge: string,
  expectedOrigin: string,
): Uint8Array {
  const raw = base64urlDecode(clientDataJSONB64);
  const text = new TextDecoder().decode(raw);
  const cd: ClientData = JSON.parse(text);

  if (cd.type !== expectedType) throw new TypeMismatchError();
  if (cd.challenge !== expectedChallenge) throw new ChallengeMismatchError();
  if (cd.origin !== expectedOrigin) throw new OriginMismatchError();
  if (cd.tokenBinding?.status === "present") throw new TokenBindingUnsupportedError();

  return raw;
}
