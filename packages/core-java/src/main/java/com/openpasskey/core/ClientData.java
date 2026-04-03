package com.openpasskey.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Client data JSON verification.
 */
public final class ClientData {
    private ClientData() {}

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    /**
     * Verifies the clientDataJSON and returns the raw decoded bytes.
     */
    public static byte[] verify(String clientDataJSONB64, String expectedType,
                                String expectedChallenge, String expectedOrigin)
            throws WebAuthnException {
        byte[] raw = Base64Url.decode(clientDataJSONB64);
        JsonNode json;
        try {
            json = JSON_MAPPER.readTree(raw);
        } catch (Exception e) {
            throw new WebAuthnException("invalid_client_data", "Failed to parse clientDataJSON");
        }

        // Verify type
        String type = json.has("type") ? json.get("type").asText() : null;
        if (!expectedType.equals(type)) {
            throw new WebAuthnException("type_mismatch",
                    "Expected type '" + expectedType + "' but got '" + type + "'");
        }

        // Verify challenge
        String challenge = json.has("challenge") ? json.get("challenge").asText() : null;
        if (!expectedChallenge.equals(challenge)) {
            throw new WebAuthnException("challenge_mismatch",
                    "Challenge does not match expected value");
        }

        // Verify origin
        String origin = json.has("origin") ? json.get("origin").asText() : null;
        if (!expectedOrigin.equals(origin)) {
            throw new WebAuthnException("origin_mismatch",
                    "Expected origin '" + expectedOrigin + "' but got '" + origin + "'");
        }

        // Check token binding
        if (json.has("tokenBinding")) {
            JsonNode tb = json.get("tokenBinding");
            if (tb.has("status") && "present".equals(tb.get("status").asText())) {
                throw new WebAuthnException("token_binding_unsupported",
                        "Token binding status 'present' is not supported");
            }
        }

        return raw;
    }
}
