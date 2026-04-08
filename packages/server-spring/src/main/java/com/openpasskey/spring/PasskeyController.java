package com.openpasskey.spring;

import com.openpasskey.core.WebAuthnException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * REST controller exposing 4 POST endpoints for WebAuthn registration and authentication.
 */
@RestController
@RequestMapping("${open-passkey.base-path:/passkey}")
public class PasskeyController {

    private final PasskeyService passkeyService;

    public PasskeyController(PasskeyService passkeyService) {
        this.passkeyService = passkeyService;
    }

    @PostMapping("/register/begin")
    public ResponseEntity<?> beginRegistration(@RequestBody Map<String, String> body) {
        try {
            var result = passkeyService.beginRegistration(
                body.get("userId"),
                body.get("username")
            );
            return ResponseEntity.ok(result);
        } catch (Stores.PasskeyException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register/finish")
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> finishRegistration(@RequestBody Map<String, Object> body) {
        try {
            var result = passkeyService.finishRegistration(
                (String) body.get("userId"),
                (Map<String, Object>) body.get("credential"),
                (Boolean) body.get("prfSupported")
            );

            if (passkeyService.isSessionEnabled() && result.containsKey("sessionToken")) {
                String token = (String) result.get("sessionToken");
                Session.SessionConfig config = passkeyService.getSessionConfig();
                String setCookie = Session.buildSetCookieHeader(token, config);

                Map<String, Object> responseBody = new LinkedHashMap<>(result);
                responseBody.remove("sessionToken");

                return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, setCookie)
                    .body(responseBody);
            }

            return ResponseEntity.ok(result);
        } catch (Stores.PasskeyException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getMessage()));
        } catch (WebAuthnException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login/begin")
    public ResponseEntity<?> beginAuthentication(@RequestBody(required = false) Map<String, String> body) {
        try {
            String userId = body != null ? body.get("userId") : null;
            var result = passkeyService.beginAuthentication(userId);
            return ResponseEntity.ok(result);
        } catch (Stores.PasskeyException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/login/finish")
    @SuppressWarnings("unchecked")
    public ResponseEntity<?> finishAuthentication(@RequestBody Map<String, Object> body) {
        try {
            var result = passkeyService.finishAuthentication(
                (String) body.get("userId"),
                (Map<String, Object>) body.get("credential")
            );

            if (passkeyService.isSessionEnabled() && result.containsKey("sessionToken")) {
                String token = (String) result.get("sessionToken");
                Session.SessionConfig config = passkeyService.getSessionConfig();
                String setCookie = Session.buildSetCookieHeader(token, config);

                // Remove sessionToken from response body — it's in the cookie
                Map<String, Object> responseBody = new LinkedHashMap<>(result);
                responseBody.remove("sessionToken");

                return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, setCookie)
                    .body(responseBody);
            }

            return ResponseEntity.ok(result);
        } catch (Stores.PasskeyException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getMessage()));
        } catch (WebAuthnException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/session")
    public ResponseEntity<?> session(@RequestHeader(value = "Cookie", required = false) String cookieHeader) {
        if (!passkeyService.isSessionEnabled()) {
            return ResponseEntity.status(404).body(Map.of("error", "session not configured"));
        }

        Session.SessionConfig config = passkeyService.getSessionConfig();
        String token = Session.parseCookieToken(cookieHeader, config);
        if (token == null) {
            return ResponseEntity.status(401).body(Map.of("error", "no session"));
        }

        try {
            Session.SessionTokenData data = passkeyService.getSessionTokenData(token);
            return ResponseEntity.ok(Map.of("userId", data.userId(), "authenticated", true));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout() {
        if (!passkeyService.isSessionEnabled()) {
            return ResponseEntity.status(404).body(Map.of("error", "session not configured"));
        }

        Session.SessionConfig config = passkeyService.getSessionConfig();
        String clearCookie = Session.buildClearCookieHeader(config);

        return ResponseEntity.ok()
            .header(HttpHeaders.SET_COOKIE, clearCookie)
            .body(Map.of("success", true));
    }
}
