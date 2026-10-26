package com.jwtbreaker;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Helper methods for detecting and decoding JSON Web Tokens.
 */
public final class JwtUtils {

    // Matches a 3-part JWT. Signature part may be empty (e.g. alg:none tokens).
    private static final Pattern JWT_PATTERN = Pattern.compile(
            "eyJ[a-zA-Z0-9_-]+\\.eyJ[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]*");

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwtUtils() {
    }

    /** True if the value looks like a JWT. */
    public static boolean isJwt(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        return JWT_PATTERN.matcher(value.trim()).matches();
    }

    /**
     * Finds the first JWT-looking substring inside a larger value such as an
     * Authorization or Cookie header. Returns null if none found.
     */
    public static String extractJwt(String value) {
        if (value == null) {
            return null;
        }
        var matcher = JWT_PATTERN.matcher(value);
        return matcher.find() ? matcher.group() : null;
    }

    /** Base64Url-decodes one JWT segment to a UTF-8 string. */
    public static String decodeSegment(String segment) {
        byte[] decoded = Base64.getUrlDecoder().decode(segment);
        return new String(decoded, StandardCharsets.UTF_8);
    }

    /** Pretty-prints a JSON string. Falls back to the raw text if invalid. */
    public static String prettyJson(String json) {
        try {
            Object obj = MAPPER.readValue(json, Object.class);
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(obj);
        } catch (Exception e) {
            return json;
        }
    }

    /**
     * Decodes a JWT without verifying its signature.
     * Returns a DecodedJwt with pretty-printed header and payload JSON.
     */
    public static DecodedJwt decodeJwt(String token) {
        String[] parts = token.split("\\.", -1);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Not a valid JWT: expected at least 2 segments");
        }

        String headerJson = decodeSegment(parts[0]);
        String payloadJson = decodeSegment(parts[1]);
        String signature = parts.length >= 3 ? parts[2] : "";

        return new DecodedJwt(
                prettyJson(headerJson),
                prettyJson(payloadJson),
                headerJson,
                payloadJson,
                signature);
    }

    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    /** Base64Url-encodes bytes without padding (JWT style). */
    public static String base64Url(byte[] data) {
        return URL_ENCODER.encodeToString(data);
    }

    /** Base64Url-encodes a UTF-8 string without padding. */
    public static String base64Url(String text) {
        return base64Url(text.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Builds an "alg:none" token from an existing payload. Header is forced to
     * {"alg":"none","typ":"JWT"} and the signature is left empty.
     */
    public static String generateAlgNoneToken(String payloadRawJson) {
        String header = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        return base64Url(header) + "." + base64Url(payloadRawJson) + ".";
    }

    /** Computes the Base64Url HMAC-SHA256 signature of the signing input. */
    public static String hmacSha256(String signingInput, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            return base64Url(sig);
        } catch (Exception e) {
            throw new RuntimeException("HMAC error: " + e.getMessage(), e);
        }
    }

    /**
     * True if the given secret correctly signs this HS256 token, i.e. the token
     * is signed with that weak secret.
     */
    public static boolean verifyHs256(String token, String secret) {
        String[] parts = token.split("\\.", -1);
        if (parts.length < 3 || parts[2].isEmpty()) {
            return false;
        }
        String signingInput = parts[0] + "." + parts[1];
        String expected = hmacSha256(signingInput, secret);
        return constantTimeEquals(expected, parts[2]);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    /**
     * Reads the "exp" claim (epoch seconds) from a payload JSON string.
     * Returns null if there is no exp claim.
     */
    public static Long readExp(String payloadJson) {
        try {
            JsonNode root = MAPPER.readTree(payloadJson);
            JsonNode exp = root.get("exp");
            if (exp == null || exp.isNull()) {
                return null;
            }
            return exp.asLong();
        } catch (Exception e) {
            return null;
        }
    }

    /** Holder for a decoded JWT. */
    public static final class DecodedJwt {
        public final String headerPretty;
        public final String payloadPretty;
        public final String headerRaw;
        public final String payloadRaw;
        public final String signature;

        public DecodedJwt(String headerPretty, String payloadPretty,
                          String headerRaw, String payloadRaw, String signature) {
            this.headerPretty = headerPretty;
            this.payloadPretty = payloadPretty;
            this.headerRaw = headerRaw;
            this.payloadRaw = payloadRaw;
            this.signature = signature;
        }
    }
}
