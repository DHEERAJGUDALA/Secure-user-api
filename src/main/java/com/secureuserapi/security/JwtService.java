package com.secureuserapi.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Handles all JWT operations:
 * - Generate access tokens
 * - Generate refresh tokens
 * - Validate tokens
 * - Extract claims (email, expiry, tokenVersion)
 *
 * Uses HS256 (HMAC-SHA256) symmetric signing — same key to sign and verify.
 */
@Service
public class JwtService {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    // ─── Token Generation ────────────────────────────────────────────────────

    /**
     * Generate access token for a user.
     * Embeds: email (subject), role, tokenVersion, issued-at, expiry.
     */
    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        // Cast to our User entity to access extra fields
        if (userDetails instanceof com.secureuserapi.entity.User user) {
            claims.put("role", user.getRole().name());
            claims.put("tokenVersion", user.getTokenVersion());
        }

        return buildToken(claims, userDetails.getUsername(), jwtExpiration);
    }

    /**
     * Generate refresh token — minimal claims, longer expiry.
     * Only used to obtain a new access token.
     */
    public String generateRefreshToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();

        if (userDetails instanceof com.secureuserapi.entity.User user) {
            claims.put("tokenVersion", user.getTokenVersion());
        }

        return buildToken(claims, userDetails.getUsername(), refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, String subject, long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(subject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSigningKey())
                .compact();
    }

    // ─── Token Validation ────────────────────────────────────────────────────

    /**
     * Validates token against the user:
     * 1. Email in token matches user's email
     * 2. Token is not expired
     * 3. tokenVersion in token matches current user's tokenVersion
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String email = extractEmail(token);

        boolean emailMatches = email.equals(userDetails.getUsername());
        boolean notExpired = !isTokenExpired(token);
        boolean versionMatches = true;

        // Check tokenVersion to catch invalidated tokens
        if (userDetails instanceof com.secureuserapi.entity.User user) {
            Integer tokenVersionInJwt = extractClaim(token, claims ->
                    claims.get("tokenVersion", Integer.class));
            versionMatches = tokenVersionInJwt != null &&
                    tokenVersionInJwt == user.getTokenVersion();
        }

        return emailMatches && notExpired && versionMatches;
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ─── Claims Extraction ───────────────────────────────────────────────────

    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public long getJwtExpiration() {
        return jwtExpiration;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // ─── Key ─────────────────────────────────────────────────────────────────

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
