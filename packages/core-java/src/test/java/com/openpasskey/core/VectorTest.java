package com.openpasskey.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Loads shared spec vectors from ../../spec/vectors/ and runs them against the Java implementation.
 * This is the cross-language contract test.
 */
public class VectorTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Resolve the vectors directory relative to the project root.
     * Tries multiple strategies to locate it.
     */
    private static Path vectorsDir() {
        // Try relative to project dir (standard Maven execution)
        Path projectDir = Paths.get(System.getProperty("user.dir"));
        Path candidate = projectDir.resolve("../../spec/vectors").normalize();
        if (Files.isDirectory(candidate)) {
            return candidate;
        }
        // Fallback: try from test resources (if vectors are copied there)
        candidate = Paths.get("src/test/resources/vectors");
        if (Files.isDirectory(candidate)) {
            return candidate;
        }
        throw new RuntimeException("Cannot find spec/vectors directory. Tried: "
                + projectDir.resolve("../../spec/vectors").normalize());
    }

    private static JsonNode loadVectors(String filename) throws IOException {
        Path path = vectorsDir().resolve(filename);
        return JSON.readTree(Files.readString(path));
    }

    @TestFactory
    Collection<DynamicTest> registrationVectors() throws IOException {
        JsonNode root = loadVectors("registration.json");
        JsonNode vectors = root.get("vectors");
        List<DynamicTest> tests = new ArrayList<>();

        for (JsonNode vector : vectors) {
            String name = vector.get("name").asText();
            tests.add(DynamicTest.dynamicTest("registration: " + name, () -> {
                JsonNode input = vector.get("input");
                JsonNode expected = vector.get("expected");
                JsonNode credential = input.get("credential");
                JsonNode response = credential.get("response");

                try {
                    RegistrationResult result = WebAuthn.verifyRegistration(new RegistrationInput(
                            input.get("rpId").asText(),
                            input.get("expectedChallenge").asText(),
                            input.get("expectedOrigin").asText(),
                            response.get("clientDataJSON").asText(),
                            response.get("attestationObject").asText()
                    ));

                    assertTrue(expected.get("success").asBoolean(),
                            "Expected failure but verification succeeded");

                    if (expected.has("credentialId")) {
                        assertEquals(expected.get("credentialId").asText(),
                                Base64Url.encode(result.getCredentialId()));
                    }
                    if (expected.has("publicKeyCose")) {
                        assertEquals(expected.get("publicKeyCose").asText(),
                                Base64Url.encode(result.getPublicKeyCose()));
                    }
                    if (expected.has("signCount")) {
                        assertEquals(expected.get("signCount").asInt(), result.getSignCount());
                    }
                    if (expected.has("rpIdHash")) {
                        assertEquals(expected.get("rpIdHash").asText(),
                                Base64Url.encode(result.getRpIdHash()));
                    }
                } catch (WebAuthnException e) {
                    assertFalse(expected.get("success").asBoolean(),
                            "Expected success but got error: " + e.getCode() + " - " + e.getMessage());
                    assertEquals(expected.get("error").asText(), e.getCode(),
                            "Error code mismatch: " + e.getMessage());
                }
            }));
        }
        return tests;
    }

    @TestFactory
    Collection<DynamicTest> authenticationVectors() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        tests.addAll(buildAuthenticationTests("authentication.json", "authentication"));
        return tests;
    }

    @TestFactory
    Collection<DynamicTest> hybridAuthenticationVectors() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        tests.addAll(buildAuthenticationTests("hybrid_authentication.json", "hybrid"));
        return tests;
    }

    private List<DynamicTest> buildAuthenticationTests(String filename, String prefix)
            throws IOException {
        JsonNode root = loadVectors(filename);
        JsonNode vectors = root.get("vectors");
        List<DynamicTest> tests = new ArrayList<>();

        for (JsonNode vector : vectors) {
            String name = vector.get("name").asText();
            tests.add(DynamicTest.dynamicTest(prefix + ": " + name, () -> {
                JsonNode input = vector.get("input");
                JsonNode expected = vector.get("expected");
                JsonNode credential = input.get("credential");
                JsonNode response = credential.get("response");

                try {
                    AuthenticationResult result = WebAuthn.verifyAuthentication(new AuthenticationInput(
                            input.get("rpId").asText(),
                            input.get("expectedChallenge").asText(),
                            input.get("expectedOrigin").asText(),
                            input.get("storedPublicKeyCose").asText(),
                            input.get("storedSignCount").asInt(),
                            response.get("clientDataJSON").asText(),
                            response.get("authenticatorData").asText(),
                            response.get("signature").asText()
                    ));

                    assertTrue(expected.get("success").asBoolean(),
                            "Expected failure but verification succeeded");

                    if (expected.has("signCount")) {
                        assertEquals(expected.get("signCount").asInt(), result.getSignCount());
                    }
                } catch (WebAuthnException e) {
                    assertFalse(expected.get("success").asBoolean(),
                            "Expected success but got error: " + e.getCode() + " - " + e.getMessage());
                    assertEquals(expected.get("error").asText(), e.getCode(),
                            "Error code mismatch: " + e.getMessage());
                }
            }));
        }
        return tests;
    }
}
