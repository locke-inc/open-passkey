package com.openpasskey.core;

/**
 * Input parameters for WebAuthn registration verification.
 * All binary fields are base64url-encoded strings (no padding).
 */
public class RegistrationInput {
    private final String rpId;
    private final String expectedChallenge;
    private final String expectedOrigin;
    private final String clientDataJSON;
    private final String attestationObject;
    private final boolean requireUserVerification;

    public RegistrationInput(String rpId, String expectedChallenge, String expectedOrigin,
                             String clientDataJSON, String attestationObject) {
        this(rpId, expectedChallenge, expectedOrigin, clientDataJSON, attestationObject, false);
    }

    public RegistrationInput(String rpId, String expectedChallenge, String expectedOrigin,
                             String clientDataJSON, String attestationObject,
                             boolean requireUserVerification) {
        this.rpId = rpId;
        this.expectedChallenge = expectedChallenge;
        this.expectedOrigin = expectedOrigin;
        this.clientDataJSON = clientDataJSON;
        this.attestationObject = attestationObject;
        this.requireUserVerification = requireUserVerification;
    }

    public String getRpId() { return rpId; }
    public String getExpectedChallenge() { return expectedChallenge; }
    public String getExpectedOrigin() { return expectedOrigin; }
    public String getClientDataJSON() { return clientDataJSON; }
    public String getAttestationObject() { return attestationObject; }
    public boolean isRequireUserVerification() { return requireUserVerification; }
}
