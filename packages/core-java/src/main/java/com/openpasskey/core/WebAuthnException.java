package com.openpasskey.core;

/**
 * Exception thrown when WebAuthn verification fails.
 * The error code identifies the specific failure reason.
 */
public class WebAuthnException extends Exception {
    private final String code;

    public WebAuthnException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String getCode() {
        return code;
    }
}
