/**
 * Stateless HMAC-SHA256 session tokens with cookie helpers.
 * Opt-in via SessionConfig on server config.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

// --- Types ---

export interface SessionConfig {
  /** HMAC-SHA256 signing key, >= 32 characters */
  secret: string;
  /** Session duration in milliseconds, default 86400000 (24h) */
  duration?: number;
  /** Clock skew grace period in milliseconds, default 10000 (10s) */
  clockSkewGrace?: number;
  /** Cookie name, default "op_session" */
  cookieName?: string;
  /** Cookie path, default "/" */
  cookiePath?: string;
  /** Set Secure flag on cookie, default true */
  secure?: boolean;
  /** SameSite attribute, default "Lax" */
  sameSite?: "Strict" | "Lax" | "None";
  /** Cookie Domain attribute, omitted by default */
  domain?: string;
}

/** Internal token payload — never serialized to HTTP responses */
export interface SessionTokenData {
  userId: string;
  expiresAt: number;
}

// --- Constants ---

const DEFAULT_DURATION_MS = 86_400_000; // 24h
const DEFAULT_CLOCK_SKEW_GRACE_MS = 10_000; // 10s
const DEFAULT_COOKIE_NAME = "op_session";
const MIN_SECRET_LENGTH = 32;

// --- Config validation ---

export function validateSessionConfig(config: SessionConfig): void {
  if (!config.secret || config.secret.length < MIN_SECRET_LENGTH) {
    throw new Error(
      `session secret must be at least ${MIN_SECRET_LENGTH} characters`,
    );
  }
}

// --- Token helpers ---

function sign(data: string, secret: string): string {
  return createHmac("sha256", secret).update(data).digest("base64url");
}

export function createSessionToken(
  userId: string,
  config: SessionConfig,
): string {
  const duration = config.duration ?? DEFAULT_DURATION_MS;
  const expiresAt = Date.now() + duration;
  const payload = `${userId}:${expiresAt}`;
  const signature = sign(payload, config.secret);
  return `${payload}:${signature}`;
}

export function validateSessionToken(
  token: string,
  config: SessionConfig,
): SessionTokenData {
  // Split from the right — userId may contain colons
  const lastColon = token.lastIndexOf(":");
  if (lastColon === -1) throw new Error("invalid session token");

  const secondLastColon = token.lastIndexOf(":", lastColon - 1);
  if (secondLastColon === -1) throw new Error("invalid session token");

  const userId = token.slice(0, secondLastColon);
  const expiresAtStr = token.slice(secondLastColon + 1, lastColon);
  const providedSig = token.slice(lastColon + 1);

  if (!userId || !expiresAtStr || !providedSig) {
    throw new Error("invalid session token");
  }

  const expiresAt = Number(expiresAtStr);
  if (!Number.isFinite(expiresAt)) throw new Error("invalid session token");

  // Timing-safe signature comparison
  const payload = `${userId}:${expiresAtStr}`;
  const expectedSig = sign(payload, config.secret);

  const sigBuf = Buffer.from(providedSig);
  const expectedBuf = Buffer.from(expectedSig);

  if (
    sigBuf.length !== expectedBuf.length ||
    !timingSafeEqual(sigBuf, expectedBuf)
  ) {
    throw new Error("invalid session token");
  }

  // Expiry check with clock skew grace
  const grace = config.clockSkewGrace ?? DEFAULT_CLOCK_SKEW_GRACE_MS;
  if (Date.now() > expiresAt + grace) {
    throw new Error("session expired");
  }

  return { userId, expiresAt };
}

// --- Cookie helpers ---

export function buildSetCookieHeader(
  token: string,
  config: SessionConfig,
): string {
  const name = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const path = config.cookiePath ?? "/";
  const sameSite = config.sameSite ?? "Lax";
  const duration = config.duration ?? DEFAULT_DURATION_MS;
  const maxAge = Math.floor(duration / 1000);

  const parts = [
    `${name}=${token}`,
    `HttpOnly`,
    `Path=${path}`,
    `Max-Age=${maxAge}`,
    `SameSite=${sameSite}`,
  ];

  if (config.secure !== false) {
    parts.push("Secure");
  }

  if (config.domain) {
    parts.push(`Domain=${config.domain}`);
  }

  return parts.join("; ");
}

export function buildClearCookieHeader(config: SessionConfig): string {
  const name = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const path = config.cookiePath ?? "/";
  const sameSite = config.sameSite ?? "Lax";

  const parts = [
    `${name}=`,
    `HttpOnly`,
    `Path=${path}`,
    `Max-Age=0`,
    `SameSite=${sameSite}`,
  ];

  if (config.secure !== false) {
    parts.push("Secure");
  }

  if (config.domain) {
    parts.push(`Domain=${config.domain}`);
  }

  return parts.join("; ");
}

export function parseCookieToken(
  cookieHeader: string | null | undefined,
  config: SessionConfig,
): string | null {
  if (!cookieHeader) return null;

  const name = config.cookieName ?? DEFAULT_COOKIE_NAME;
  const prefix = `${name}=`;

  const cookies = cookieHeader.split(";");
  for (const cookie of cookies) {
    const trimmed = cookie.trim();
    if (trimmed.startsWith(prefix)) {
      const value = trimmed.slice(prefix.length);
      return value || null;
    }
  }

  return null;
}
