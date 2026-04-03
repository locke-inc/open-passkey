package com.openpasskey.core;

/**
 * Input parameters for WebAuthn authentication verification.
 * All binary fields are base64url-encoded strings (no padding).
 */
public class AuthenticationInput {
    private final String rpId;
    private final String expectedChallenge;
    private final String expectedOrigin;
    private final String storedPublicKeyCose;
    private final int storedSignCount;
    private final String clientDataJSON;
    private final String authenticatorData;
    private final String signature;
    private final boolean requireUserVerification;

    public AuthenticationInput(String rpId, String expectedChallenge, String expectedOrigin,
                               String storedPublicKeyCose, int storedSignCount,
                               String clientDataJSON, String authenticatorData, String signature) {
        this(rpId, expectedChallenge, expectedOrigin, storedPublicKeyCose, storedSignCount,
             clientDataJSON, authenticatorData, signature, false);
    }

    public AuthenticationInput(String rpId, String expectedChallenge, String expectedOrigin,
                               String storedPublicKeyCose, int storedSignCount,
                               String clientDataJSON, String authenticatorData, String signature,
                               boolean requireUserVerification) {
        this.rpId = rpId;
        this.expectedChallenge = expectedChallenge;
        this.expectedOrigin = expectedOrigin;
        this.storedPublicKeyCose = storedPublicKeyCose;
        this.storedSignCount = storedSignCount;
        this.clientDataJSON = clientDataJSON;
        this.authenticatorData = authenticatorData;
        this.signature = signature;
        this.requireUserVerification = requireUserVerification;
    }

    public String getRpId() { return rpId; }
    public String getExpectedChallenge() { return expectedChallenge; }
    public String getExpectedOrigin() { return expectedOrigin; }
    public String getStoredPublicKeyCose() { return storedPublicKeyCose; }
    public int getStoredSignCount() { return storedSignCount; }
    public String getClientDataJSON() { return clientDataJSON; }
    public String getAuthenticatorData() { return authenticatorData; }
    public String getSignature() { return signature; }
    public boolean isRequireUserVerification() { return requireUserVerification; }
}
