package com.example.authhub.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final Key key;
    private final long accessTokenExpireMs;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-validity-seconds}") long accessTokenValiditySeconds
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpireMs = accessTokenValiditySeconds * 1000L;
    }

    public boolean validate(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // clientId 포함
    public String createAccessToken(Long userId, String email, String clientId, List<String> roles) {
        long now = System.currentTimeMillis();
        long expiry = now + accessTokenExpireMs;

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(email)
                .claim("userId", userId)
                .claim("clientId", clientId)
                .claim("roles", roles)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expiry))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getJti(String token) {
        return parseClaims(token).getId();
    }

    public Long getUserId(String token) {
        Object userId = parseClaims(token).get("userId");
        return userId == null ? null : Long.valueOf(userId.toString());
    }

    // clientId getter
    public String getClientId(String token) {
        Object v = parseClaims(token).get("clientId");
        return v == null ? null : v.toString();
    }

    public long getIssuedAtMillis(String token) {
        Date issuedAt = parseClaims(token).getIssuedAt();
        return issuedAt == null ? 0L : issuedAt.getTime();
    }

    public long getRemainingValiditySeconds(String token) {
        Date expiration = parseClaims(token).getExpiration();
        return Math.max((expiration.getTime() - System.currentTimeMillis()) / 1000, 0);
    }

    public long getAccessTokenValiditySeconds() {
        return accessTokenExpireMs / 1000L;
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);
        String email = claims.getSubject();

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");

        List<SimpleGrantedAuthority> authorities = roles.stream()
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .map(SimpleGrantedAuthority::new)
                .toList();

        User principal = new User(email, "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
