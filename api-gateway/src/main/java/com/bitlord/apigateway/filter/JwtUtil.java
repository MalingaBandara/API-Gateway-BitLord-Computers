package com.bitlord.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

import javax.crypto.SecretKey;

/**
 * Utility class for JWT token operations at the API Gateway level.
 * Handles token validation and claims extraction using the shared secret key.
 */
@Component
public class JwtUtil {

    // Secret key loaded from application.yml (app.jwt.secret) — stored as a Base64 encoded string
    @Value("${app.jwt.secret}")
    private String secretKey;

    /**
     * Validates the given JWT token against the secret key.
     * Throws an exception if the token is expired, malformed, or tampered with.
     *
     * @param token - the raw JWT token string (without "Bearer " prefix)
     */
    public void validateToken(final String token) {
        Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token);
    }

    /**
     * Extracts and returns the claims (payload) from the JWT token.
     * Claims contain data like userId, role, expiration, etc.
     *
     * @param token - the raw JWT token string (without "Bearer " prefix)
     * @return Claims - the decoded payload of the token
     */
    public Claims getClaims(final String token) {
        return Jwts.parser().verifyWith(getSignKey()).build().parseSignedClaims(token).getPayload();
    }

    /**
     * Decodes the Base64 secret key from config and builds a secure HMAC-SHA signing key.
     * This key is used to both verify the token signature and parse its contents.
     *
     * @return SecretKey - the cryptographic key used for JWT signature verification
     */
    private SecretKey getSignKey() {
        // Decode the Base64 encoded secret string into raw bytes
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);

        // Build an HMAC-SHA key from the decoded bytes (matches the key used when the token was signed)
        return Keys.hmacShaKeyFor(keyBytes);
    }
}