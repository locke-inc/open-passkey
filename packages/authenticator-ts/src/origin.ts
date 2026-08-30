import { getDomain, parse } from "tldts";

function isLoopbackHost(hostname: string): boolean {
  return hostname === "localhost";
}

function parseWebOrigin(origin: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error("Invalid WebAuthn origin");
  }

  if (
    parsed.origin !== origin ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLoopbackHost(parsed.hostname)))
  ) {
    throw new Error("Invalid WebAuthn origin");
  }
  return parsed;
}

export function validateRpIdForOrigin(rpId: string, origin: string): void {
  const parsedOrigin = parseWebOrigin(origin);
  const normalizedRpId = rpId.toLowerCase();
  const rpIdDetails = parse(rpId, { allowPrivateDomains: true });

  let parsedRpId: URL;
  try {
    parsedRpId = new URL(`https://${rpId}`);
  } catch {
    throw new Error("Invalid RP ID");
  }

  if (
    rpId !== normalizedRpId ||
    rpIdDetails.isIp ||
    rpId.endsWith(".") ||
    parsedRpId.hostname !== rpId ||
    parsedRpId.port !== "" ||
    parsedRpId.pathname !== "/" ||
    parsedRpId.search !== "" ||
    parsedRpId.hash !== ""
  ) {
    throw new Error("Invalid RP ID");
  }

  const originHost = parsedOrigin.hostname;
  if (originHost !== rpId && !originHost.endsWith(`.${rpId}`)) {
    throw new Error("RP ID is not valid for origin");
  }
  if (originHost === rpId) {
    return;
  }

  const registrableDomain = getDomain(originHost, { allowPrivateDomains: true });
  if (
    registrableDomain === null ||
    (rpId !== registrableDomain && !rpId.endsWith(`.${registrableDomain}`))
  ) {
    throw new Error("RP ID is not a registrable domain suffix");
  }
}

export function validateCeremonyContext(
  rpId: string,
  origin: string,
  topOrigin: string | undefined,
  crossOrigin = false,
): void {
  validateRpIdForOrigin(rpId, origin);

  if (!crossOrigin) {
    if (topOrigin !== undefined) {
      throw new Error("topOrigin requires a cross-origin ceremony");
    }
    return;
  }

  if (topOrigin === undefined || topOrigin === origin) {
    throw new Error("Cross-origin ceremonies require a distinct topOrigin");
  }
  parseWebOrigin(topOrigin);
}

export function encodeCollectedClientData(
  type: "webauthn.create" | "webauthn.get",
  challenge: string,
  origin: string,
  topOrigin: string | undefined,
  crossOrigin = false,
): Uint8Array {
  const clientData: Record<string, string | boolean> = {
    type,
    challenge,
    origin,
    crossOrigin,
  };
  if (crossOrigin) {
    clientData.topOrigin = topOrigin!;
  }
  return new TextEncoder().encode(JSON.stringify(clientData));
}
