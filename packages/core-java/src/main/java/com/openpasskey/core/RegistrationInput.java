package com.openpasskey.core;

import java.util.List;

/**
 * Input parameters for WebAuthn registration verification.
 * All binary fields are base64url-encoded strings (no padding).
 */
public class RegistrationInput {
    private final String rpId;
    private final String expectedChallenge;
    private final String expectedOrigin;
    private final List<String> additionalOrigins;
    private final String clientDataJSON;
    private final String attestationObject;
    private final boolean requireUserVerification;

    public RegistrationInput(String rpId, String expectedChallenge, String expectedOrigin,
                             String clientDataJSON, String attestationObject) {
        this(rpId, expectedChallenge, expectedOrigin, null, clientDataJSON, attestationObject, false);
    }

    public RegistrationInput(String rpId, String expectedChallenge, String expectedOrigin,
                             String clientDataJSON, String attestationObject,
                             boolean requireUserVerification) {
        this(rpId, expectedChallenge, expectedOrigin, null, clientDataJSON, attestationObject, requireUserVerification);
    }

    public RegistrationInput(String rpId, String expectedChallenge, String expectedOrigin,
                             List<String> additionalOrigins,
                             String clientDataJSON, String attestationObject,
                             boolean requireUserVerification) {
        this.rpId = rpId;
        this.expectedChallenge = expectedChallenge;
        this.expectedOrigin = expectedOrigin;
        this.additionalOrigins = additionalOrigins;
        this.clientDataJSON = clientDataJSON;
        this.attestationObject = attestationObject;
        this.requireUserVerification = requireUserVerification;
    }

    public String getRpId() { return rpId; }
    public String getExpectedChallenge() { return expectedChallenge; }
    public String getExpectedOrigin() { return expectedOrigin; }
    public List<String> getAdditionalOrigins() { return additionalOrigins; }
    public String getClientDataJSON() { return clientDataJSON; }
    public String getAttestationObject() { return attestationObject; }
    public boolean isRequireUserVerification() { return requireUserVerification; }
}
