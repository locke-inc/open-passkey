package com.openpasskey.spring;

import com.openpasskey.core.WebAuthn;
import com.openpasskey.core.RegistrationInput;
import com.openpasskey.core.RegistrationResult;
import com.openpasskey.core.AuthenticationInput;
import com.openpasskey.core.AuthenticationResult;
import com.openpasskey.core.WebAuthnException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.util.*;

/**
 * Core passkey service that orchestrates challenge management and WebAuthn verification.
 */
public class PasskeyService {

    private static final Logger log = LoggerFactory.getLogger(PasskeyService.class);

    private final PasskeyProperties props;
    private final Stores.ChallengeStore challengeStore;
    private final Stores.CredentialStore credentialStore;
    private final SecureRandom random = new SecureRandom();
    private final Session.SessionConfig sessionConfig;

    public PasskeyService(PasskeyProperties props,
                          Stores.ChallengeStore challengeStore,
                          Stores.CredentialStore credentialStore) {
        props.validate();
        this.props = props;
        this.challengeStore = challengeStore;
        this.credentialStore = credentialStore;
        this.sessionConfig = props.isSessionEnabled() ? props.buildSessionConfig() : null;
    }

    public boolean isSessionEnabled() {
        return sessionConfig != null;
    }

    public Session.SessionConfig getSessionConfig() {
        return sessionConfig;
    }

    private String generateChallenge() {
        byte[] buf = new byte[props.getChallengeLength()];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private String b64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    private byte[] b64urlDecode(String s) {
        return Base64.getUrlDecoder().decode(s + "=".repeat((4 - s.length() % 4) % 4));
    }

    // --- Begin Registration ---

    public Map<String, Object> beginRegistration(String userId, String username) throws Stores.PasskeyException {
        if (userId == null || userId.isBlank() || username == null || username.isBlank()) {
            throw new Stores.PasskeyException("userId is required");
        }

        List<Stores.StoredCredential> existing = credentialStore.getByUser(userId);

        if (!props.isAllowMultipleCredentials() && !existing.isEmpty()) {
            throw new Stores.PasskeyException("user already registered", 409);
        }

        String challenge = generateChallenge();
        byte[] prfSalt = new byte[32];
        random.nextBytes(prfSalt);

        String challengeData = "{\"challenge\":\"" + challenge + "\",\"prfSalt\":\"" + b64url(prfSalt) + "\"}";
        challengeStore.store(userId, challengeData, props.getChallengeTimeoutSeconds());

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challenge);
        options.put("rp", Map.of("id", props.getRpId(), "name", props.getRpDisplayName()));
        options.put("user", Map.of(
            "id", b64url(userId.getBytes()),
            "name", username,
            "displayName", username
        ));
        options.put("pubKeyCredParams", List.of(
            Map.of("type", "public-key", "alg", -52),
            Map.of("type", "public-key", "alg", -49),
            Map.of("type", "public-key", "alg", -7)
        ));
        options.put("authenticatorSelection", Map.of(
            "residentKey", "preferred",
            "userVerification", "preferred"
        ));
        options.put("timeout", props.getChallengeTimeoutSeconds() * 1000);
        options.put("attestation", "none");
        options.put("extensions", Map.of(
            "prf", Map.of("eval", Map.of("first", b64url(prfSalt)))
        ));

        if (!existing.isEmpty()) {
            List<Map<String, Object>> excludeList = new ArrayList<>();
            for (Stores.StoredCredential c : existing) {
                excludeList.add(Map.of("type", "public-key", "id", b64url(c.credentialId())));
            }
            options.put("excludeCredentials", excludeList);
        }

        return options;
    }

    // --- Finish Registration ---

    public Map<String, Object> finishRegistration(String userId, Map<String, Object> credential, Boolean prfSupported)
            throws Stores.PasskeyException, WebAuthnException {
        String challengeDataStr = challengeStore.consume(userId);
        // Simple JSON parsing — production would use Jackson
        String storedChallenge = extractJsonValue(challengeDataStr, "challenge");
        String storedPrfSalt = extractJsonValue(challengeDataStr, "prfSalt");

        @SuppressWarnings("unchecked")
        Map<String, String> response = (Map<String, String>) credential.get("response");

        RegistrationResult result = WebAuthn.verifyRegistration(new RegistrationInput(
            props.getRpId(),
            storedChallenge,
            props.getOrigin(),
            response.get("clientDataJSON"),
            response.get("attestationObject")
        ));

        boolean prfEnabled = prfSupported != null && prfSupported;
        byte[] prfSaltBytes = prfEnabled ? b64urlDecode(storedPrfSalt) : null;

        Stores.StoredCredential cred = new Stores.StoredCredential(
            result.getCredentialId(),
            result.getPublicKeyCose(),
            result.getSignCount(),
            userId,
            prfSaltBytes,
            prfEnabled
        );
        credentialStore.store(cred);

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("credentialId", b64url(result.getCredentialId()));
        resp.put("registered", true);
        resp.put("prfSupported", prfEnabled);
        if (sessionConfig != null) {
            String token = Session.createToken(userId, sessionConfig);
            resp.put("sessionToken", token);
        }
        return resp;
    }

    // --- Begin Authentication ---

    public Map<String, Object> beginAuthentication(String userId) throws Stores.PasskeyException {
        String challenge = generateChallenge();
        String challengeKey = (userId != null && !userId.isBlank()) ? userId : challenge;
        challengeStore.store(challengeKey, challenge, props.getChallengeTimeoutSeconds());

        Map<String, Object> options = new LinkedHashMap<>();
        options.put("challenge", challenge);
        options.put("rpId", props.getRpId());
        options.put("timeout", props.getChallengeTimeoutSeconds() * 1000);
        options.put("userVerification", "preferred");

        if (userId != null && !userId.isBlank()) {
            List<Map<String, Object>> allowCredentials = new ArrayList<>();
            Map<String, Map<String, String>> evalByCredential = new LinkedHashMap<>();
            boolean hasPrf = false;

            List<Stores.StoredCredential> creds = credentialStore.getByUser(userId);
            for (Stores.StoredCredential c : creds) {
                String credIdEncoded = b64url(c.credentialId());
                allowCredentials.add(Map.of("type", "public-key", "id", credIdEncoded));
                if (c.prfSupported() && c.prfSalt() != null) {
                    evalByCredential.put(credIdEncoded, Map.of("first", b64url(c.prfSalt())));
                    hasPrf = true;
                }
            }
            options.put("allowCredentials", allowCredentials);
            if (hasPrf) {
                options.put("extensions", Map.of("prf", Map.of("evalByCredential", evalByCredential)));
            }
        }

        return options;
    }

    // --- Finish Authentication ---

    public Map<String, Object> finishAuthentication(String userId, Map<String, Object> credential)
            throws Stores.PasskeyException, WebAuthnException {
        String challenge = challengeStore.consume(userId);

        String credId = (String) credential.get("id");
        byte[] credIdBytes = b64urlDecode(credId);
        Stores.StoredCredential stored = credentialStore.get(credIdBytes);

        @SuppressWarnings("unchecked")
        Map<String, String> response = (Map<String, String>) credential.get("response");

        String userHandle = response.get("userHandle");
        if (userHandle != null && !userHandle.isEmpty()) {
            String decoded = new String(b64urlDecode(userHandle));
            if (!decoded.equals(stored.userId())) {
                throw new Stores.PasskeyException("userHandle does not match credential owner");
            }
        }

        AuthenticationResult result = WebAuthn.verifyAuthentication(new AuthenticationInput(
            props.getRpId(),
            challenge,
            props.getOrigin(),
            b64url(stored.publicKeyCose()),
            (int) stored.signCount(),
            response.get("clientDataJSON"),
            response.get("authenticatorData"),
            response.get("signature")
        ));

        credentialStore.update(stored.withSignCount(result.getSignCount()));

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("userId", stored.userId());
        resp.put("authenticated", true);
        if (stored.prfSupported()) resp.put("prfSupported", true);

        if (sessionConfig != null) {
            String token = Session.createToken(stored.userId(), sessionConfig);
            resp.put("sessionToken", token);
        }

        return resp;
    }

    public Session.SessionTokenData getSessionTokenData(String token) {
        if (sessionConfig == null) {
            throw new IllegalStateException("session is not configured");
        }
        return Session.validateToken(token, sessionConfig);
    }

    private static String extractJsonValue(String json, String key) {
        int idx = json.indexOf("\"" + key + "\":\"");
        if (idx < 0) return "";
        int start = idx + key.length() + 4;
        int end = json.indexOf("\"", start);
        return json.substring(start, end);
    }
}
