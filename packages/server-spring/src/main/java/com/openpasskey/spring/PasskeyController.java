package com.openpasskey.spring;

import com.openpasskey.core.WebAuthnException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
            return ResponseEntity.ok(result);
        } catch (Stores.PasskeyException e) {
            return ResponseEntity.status(e.getStatusCode()).body(Map.of("error", e.getMessage()));
        } catch (WebAuthnException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}
