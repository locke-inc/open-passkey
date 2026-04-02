package com.openpasskey.core;

import java.util.Base64;

/**
 * Base64url encoding/decoding utilities (no padding).
 */
public final class Base64Url {
    private Base64Url() {}

    public static byte[] decode(String input) {
        return Base64.getUrlDecoder().decode(input);
    }

    public static String encode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
