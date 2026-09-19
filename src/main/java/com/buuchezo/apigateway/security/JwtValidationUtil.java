package com.buuchezo.apigateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Service
public class JwtValidationUtil {

    @Value("${jwt.secret}")
    private String SECRETKEY;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(
                SECRETKEY.getBytes(StandardCharsets.UTF_8)
        );
    }

    public void validateToken(final String token) {

        Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token);
    }

    public Claims extractClaims(final String token) {

        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractEmail(final String token) {

        Claims claims = extractClaims(token);

        /*
         * Your JWT currently uses the authenticated user's
         * email as the subject.
         */
        return claims.getSubject();
    }
}