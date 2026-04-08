package com.openpasskey.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for open-passkey.
 * Bind via application.yml:
 *   open-passkey:
 *     rp-id: example.com
 *     rp-display-name: Example
 *     origin: https://example.com
 */
@ConfigurationProperties(prefix = "open-passkey")
public class PasskeyProperties {

    private String rpId;
    private String rpDisplayName;
    private String origin;
    private int challengeLength = 32;
    private long challengeTimeoutSeconds = 300;
    private boolean allowMultipleCredentials = false;

    // Session properties
    private String sessionSecret;
    private long sessionDurationSeconds = 86400;
    private String sessionCookieName = "op_session";
    private String sessionCookiePath = "/";
    private boolean sessionSecure = true;
    private String sessionSameSite = "Lax";
    private String sessionDomain;

    public String getRpId() { return rpId; }
    public void setRpId(String rpId) { this.rpId = rpId; }

    public String getRpDisplayName() { return rpDisplayName; }
    public void setRpDisplayName(String rpDisplayName) { this.rpDisplayName = rpDisplayName; }

    public String getOrigin() { return origin; }
    public void setOrigin(String origin) { this.origin = origin; }

    public int getChallengeLength() { return challengeLength; }
    public void setChallengeLength(int challengeLength) { this.challengeLength = challengeLength; }

    public long getChallengeTimeoutSeconds() { return challengeTimeoutSeconds; }
    public void setChallengeTimeoutSeconds(long challengeTimeoutSeconds) { this.challengeTimeoutSeconds = challengeTimeoutSeconds; }

    public boolean isAllowMultipleCredentials() { return allowMultipleCredentials; }
    public void setAllowMultipleCredentials(boolean allowMultipleCredentials) { this.allowMultipleCredentials = allowMultipleCredentials; }

    public String getSessionSecret() { return sessionSecret; }
    public void setSessionSecret(String sessionSecret) { this.sessionSecret = sessionSecret; }

    public long getSessionDurationSeconds() { return sessionDurationSeconds; }
    public void setSessionDurationSeconds(long sessionDurationSeconds) { this.sessionDurationSeconds = sessionDurationSeconds; }

    public String getSessionCookieName() { return sessionCookieName; }
    public void setSessionCookieName(String sessionCookieName) { this.sessionCookieName = sessionCookieName; }

    public String getSessionCookiePath() { return sessionCookiePath; }
    public void setSessionCookiePath(String sessionCookiePath) { this.sessionCookiePath = sessionCookiePath; }

    public boolean isSessionSecure() { return sessionSecure; }
    public void setSessionSecure(boolean sessionSecure) { this.sessionSecure = sessionSecure; }

    public String getSessionSameSite() { return sessionSameSite; }
    public void setSessionSameSite(String sessionSameSite) { this.sessionSameSite = sessionSameSite; }

    public String getSessionDomain() { return sessionDomain; }
    public void setSessionDomain(String sessionDomain) { this.sessionDomain = sessionDomain; }

    public boolean isSessionEnabled() {
        return sessionSecret != null && !sessionSecret.isBlank();
    }

    public Session.SessionConfig buildSessionConfig() {
        return new Session.SessionConfig(
            sessionSecret, sessionDurationSeconds, 10_000,
            sessionCookieName, sessionCookiePath, sessionSecure, sessionSameSite, sessionDomain
        );
    }

    public void validate() {
        if (rpId == null || rpId.isBlank()) throw new IllegalArgumentException("rpId is required");
        if (origin == null || origin.isBlank()) throw new IllegalArgumentException("origin is required");
        if (rpId.contains("://") || rpId.contains("/")) {
            throw new IllegalArgumentException("rpId must be a bare domain (got " + rpId + ")");
        }
        if (!origin.startsWith("https://") && !origin.startsWith("http://")) {
            throw new IllegalArgumentException("origin must start with https:// or http:// (got " + origin + ")");
        }
    }
}
