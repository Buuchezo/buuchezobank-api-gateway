package com.buuchezo.apigateway.security;


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

    public void validateToken(final String token){
        SecretKey key = Keys.hmacShaKeyFor(SECRETKEY.getBytes(StandardCharsets.UTF_8));
        Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token);

    }
}
