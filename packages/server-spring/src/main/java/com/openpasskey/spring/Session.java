package com.openpasskey.spring;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class Session {

    private static final int MIN_SECRET_LENGTH = 32;
    private static final long DEFAULT_DURATION_SECONDS = 86400; // 24h
    private static final long DEFAULT_CLOCK_SKEW_GRACE_MS = 10_000; // 10s
    private static final String DEFAULT_COOKIE_NAME = "op_session";

    public record SessionConfig(
            String secret,
            long durationSeconds,
            long clockSkewGraceMs,
            String cookieName,
            String cookiePath,
            boolean secure,
            String sameSite,
            String domain
    ) {
        public SessionConfig {
            if (durationSeconds < 0) durationSeconds = DEFAULT_DURATION_SECONDS;
            if (clockSkewGraceMs < 0) clockSkewGraceMs = DEFAULT_CLOCK_SKEW_GRACE_MS;
            if (cookieName == null || cookieName.isEmpty()) cookieName = DEFAULT_COOKIE_NAME;
            if (cookiePath == null || cookiePath.isEmpty()) cookiePath = "/";
            if (sameSite == null || sameSite.isEmpty()) sameSite = "Lax";
        }

        public SessionConfig(String secret) {
            this(secret, DEFAULT_DURATION_SECONDS, DEFAULT_CLOCK_SKEW_GRACE_MS, DEFAULT_COOKIE_NAME, "/", true, "Lax", null);
        }
    }

    /** Internal only — never serialized to HTTP responses */
    public record SessionTokenData(String userId, long expiresAt) {}

    public static void validate(SessionConfig config) {
        if (config.secret() == null || config.secret().length() < MIN_SECRET_LENGTH) {
            throw new IllegalArgumentException("session secret must be at least " + MIN_SECRET_LENGTH + " characters");
        }
    }

    private static String sign(String payload, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
        } catch (Exception e) {
            throw new RuntimeException("HMAC signing failed", e);
        }
    }

    public static String createToken(String userId, SessionConfig config) {
        long expiresAt = System.currentTimeMillis() + config.durationSeconds() * 1000;
        String payload = userId + ":" + expiresAt;
        String signature = sign(payload, config.secret());
        return payload + ":" + signature;
    }

    public static SessionTokenData validateToken(String token, SessionConfig config) {
        // Split from right — userId may contain colons
        int lastColon = token.lastIndexOf(':');
        if (lastColon == -1) throw new IllegalArgumentException("invalid session token");

        int secondLastColon = token.lastIndexOf(':', lastColon - 1);
        if (secondLastColon == -1) throw new IllegalArgumentException("invalid session token");

        String userId = token.substring(0, secondLastColon);
        String expiresAtStr = token.substring(secondLastColon + 1, lastColon);
        String providedSig = token.substring(lastColon + 1);

        if (userId.isEmpty() || expiresAtStr.isEmpty() || providedSig.isEmpty()) {
            throw new IllegalArgumentException("invalid session token");
        }

        long expiresAt;
        try {
            expiresAt = Long.parseLong(expiresAtStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid session token");
        }

        // Timing-safe comparison
        String payload = userId + ":" + expiresAtStr;
        String expectedSig = sign(payload, config.secret());

        if (!MessageDigest.isEqual(
                providedSig.getBytes(StandardCharsets.UTF_8),
                expectedSig.getBytes(StandardCharsets.UTF_8))) {
            throw new IllegalArgumentException("invalid session token");
        }

        // Expiry with clock skew grace
        if (System.currentTimeMillis() > expiresAt + config.clockSkewGraceMs()) {
            throw new IllegalArgumentException("session expired");
        }

        return new SessionTokenData(userId, expiresAt);
    }

    public static String buildSetCookieHeader(String token, SessionConfig config) {
        StringBuilder sb = new StringBuilder();
        sb.append(config.cookieName()).append("=").append(token);
        sb.append("; HttpOnly");
        sb.append("; Path=").append(config.cookiePath());
        sb.append("; Max-Age=").append(config.durationSeconds());
        sb.append("; SameSite=").append(config.sameSite());
        if (config.secure()) {
            sb.append("; Secure");
        }
        if (config.domain() != null && !config.domain().isEmpty()) {
            sb.append("; Domain=").append(config.domain());
        }
        return sb.toString();
    }

    public static String buildClearCookieHeader(SessionConfig config) {
        StringBuilder sb = new StringBuilder();
        sb.append(config.cookieName()).append("=");
        sb.append("; HttpOnly");
        sb.append("; Path=").append(config.cookiePath());
        sb.append("; Max-Age=0");
        sb.append("; SameSite=").append(config.sameSite());
        if (config.secure()) {
            sb.append("; Secure");
        }
        if (config.domain() != null && !config.domain().isEmpty()) {
            sb.append("; Domain=").append(config.domain());
        }
        return sb.toString();
    }

    public static String parseCookieToken(String cookieHeader, SessionConfig config) {
        if (cookieHeader == null || cookieHeader.isEmpty()) return null;
        String prefix = config.cookieName() + "=";
        for (String cookie : cookieHeader.split(";")) {
            String trimmed = cookie.trim();
            if (trimmed.startsWith(prefix)) {
                String value = trimmed.substring(prefix.length());
                return value.isEmpty() ? null : value;
            }
        }
        return null;
    }
}
