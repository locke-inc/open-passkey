package com.openpasskey.spring;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SessionTest {
    private static final String SECRET = "a]Vv3X!kP9#mW2$nQ7@rT5&jY0^uL8*dF";

    private Session.SessionConfig config() {
        return new Session.SessionConfig(SECRET);
    }

    private Session.SessionConfig config(long durationSeconds, long clockSkewGraceMs) {
        return new Session.SessionConfig(SECRET, durationSeconds, clockSkewGraceMs, "op_session", "/", true, "Lax", null);
    }

    @Test void createToken_validFormat() {
        String token = Session.createToken("user123", config());
        int lastColon = token.lastIndexOf(':');
        int secondLast = token.lastIndexOf(':', lastColon - 1);
        assertTrue(secondLast > 0);
        long expiresAt = Long.parseLong(token.substring(secondLast + 1, lastColon));
        assertTrue(expiresAt > System.currentTimeMillis());
    }

    @Test void validateToken_freshToken() {
        String token = Session.createToken("user123", config());
        Session.SessionTokenData data = Session.validateToken(token, config());
        assertEquals("user123", data.userId());
        assertTrue(data.expiresAt() > System.currentTimeMillis());
    }

    @Test void validateToken_tamperedUserId() {
        String token = Session.createToken("user123", config());
        String tampered = token.replaceFirst("user123", "evil");
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken(tampered, config()));
    }

    @Test void validateToken_tamperedSignature() {
        String token = Session.createToken("user123", config());
        String tampered = token.substring(0, token.length() - 1) + (token.endsWith("a") ? "b" : "a");
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken(tampered, config()));
    }

    @Test void validateToken_expired() throws Exception {
        Session.SessionConfig cfg = config(0, 0);
        String token = Session.createToken("user123", cfg);
        Thread.sleep(10);
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken(token, cfg));
    }

    @Test void validateToken_wrongSecret() {
        String token = Session.createToken("user123", config());
        Session.SessionConfig other = new Session.SessionConfig("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken(token, other));
    }

    @Test void validateToken_malformed() {
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken("", config()));
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken("nocolons", config()));
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken("one:colon", config()));
    }

    @Test void validateToken_userIdWithColons() {
        String token = Session.createToken("urn:user:123", config());
        Session.SessionTokenData data = Session.validateToken(token, config());
        assertEquals("urn:user:123", data.userId());
    }

    @Test void validateToken_clockSkewGraceAccepts() throws Exception {
        Session.SessionConfig cfg = config(0, 10_000);
        String token = Session.createToken("user123", cfg);
        Thread.sleep(10);
        Session.SessionTokenData data = Session.validateToken(token, cfg);
        assertEquals("user123", data.userId());
    }

    @Test void validateToken_clockSkewGraceRejects() throws Exception {
        Session.SessionConfig cfg = config(0, 0);
        String token = Session.createToken("user123", cfg);
        Thread.sleep(10);
        assertThrows(IllegalArgumentException.class, () -> Session.validateToken(token, cfg));
    }

    @Test void buildSetCookieHeader_defaults() {
        String header = Session.buildSetCookieHeader("tok", config());
        assertTrue(header.contains("op_session=tok"));
        assertTrue(header.contains("HttpOnly"));
        assertTrue(header.contains("Path=/"));
        assertTrue(header.contains("SameSite=Lax"));
        assertTrue(header.contains("Secure"));
    }

    @Test void buildClearCookieHeader_test() {
        String header = Session.buildClearCookieHeader(config());
        assertTrue(header.contains("Max-Age=0"));
    }

    @Test void rejectShortSecret() {
        assertThrows(IllegalArgumentException.class, () ->
            Session.validate(new Session.SessionConfig("short")));
    }
}
