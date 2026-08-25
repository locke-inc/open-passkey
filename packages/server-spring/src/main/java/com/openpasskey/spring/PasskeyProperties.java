package com.openpasskey.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Configuration properties for open-passkey.
 * Bind via application.yml:
 *   open-passkey:
 *     rp-id: example.com
 *     rp-display-name: Example
 *     origin: https://example.com
 *     additional-origins:
 *       - https://app.example.com
 */
@ConfigurationProperties(prefix = "open-passkey")
public class PasskeyProperties {

    private String rpId;
    private String rpDisplayName;
    private String origin;
    private List<String> additionalOrigins;
    private int challengeLength = 32;
    private long challengeTimeoutSeconds = 300;
    private boolean allowMultipleCredentials = false;

    public String getRpId() { return rpId; }
    public void setRpId(String rpId) { this.rpId = rpId; }

    public String getRpDisplayName() { return rpDisplayName; }
    public void setRpDisplayName(String rpDisplayName) { this.rpDisplayName = rpDisplayName; }

    public String getOrigin() { return origin; }
    public void setOrigin(String origin) { this.origin = origin; }

    public List<String> getAdditionalOrigins() { return additionalOrigins; }
    public void setAdditionalOrigins(List<String> additionalOrigins) { this.additionalOrigins = additionalOrigins; }

    public int getChallengeLength() { return challengeLength; }
    public void setChallengeLength(int challengeLength) { this.challengeLength = challengeLength; }

    public long getChallengeTimeoutSeconds() { return challengeTimeoutSeconds; }
    public void setChallengeTimeoutSeconds(long challengeTimeoutSeconds) { this.challengeTimeoutSeconds = challengeTimeoutSeconds; }

    public boolean isAllowMultipleCredentials() { return allowMultipleCredentials; }
    public void setAllowMultipleCredentials(boolean allowMultipleCredentials) { this.allowMultipleCredentials = allowMultipleCredentials; }

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
