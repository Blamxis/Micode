package com.micode.micode.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {

    // --- Clé secrète sécurisée (256 bits) ---
    private final Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    // --- Durée de validité du token : 24h ---
    private final long expirationMs = 24 * 60 * 60 * 1000;

    // --- Génération du token ---
    public String generateToken(String email) {
        return Jwts.builder()
                .setSubject(email)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
                .signWith(secretKey)
                .compact();
    }

    // --- Extraction de l'email depuis le token ---
    public String extractEmail(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // --- Extraction générique d'un claim ---
    public <T> T extractClaim(String token, Function<Claims, T> resolver) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return resolver.apply(claims);
    }

    // --- Vérification de la validité du token ---
    public boolean isTokenValid(String token, String email) {
        String extractedEmail = extractEmail(token);
        return extractedEmail.equals(email) && !isTokenExpired(token);
    }

    // --- Vérification expiration ---
    private boolean isTokenExpired(String token) {
        Date expiration = extractClaim(token, Claims::getExpiration);
        return expiration.before(new Date());
    }
}
