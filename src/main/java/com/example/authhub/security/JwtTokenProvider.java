package com.example.authhub.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.access-token-validity-seconds:600}")
    private long accessTokenValiditySeconds;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(Long userId, String email, List<String> roles) {
        long now = System.currentTimeMillis();
        Date issuedAt = new Date(now);
        Date expiryDate = new Date(now + accessTokenValiditySeconds * 1000);

        String rolesStr = String.join(",", roles);
        String jti = UUID.randomUUID().toString();

        return Jwts.builder()
                .setSubject(String.valueOf(userId))
                .setId(jti)
                .claim("email", email)
                .claim("roles", rolesStr)
                .setIssuedAt(issuedAt)
                .setExpiration(expiryDate)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Jws<Claims> parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    public boolean validate(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token).getBody();

        String userId = claims.getSubject();
        String email = claims.get("email", String.class);
        String rolesStr = claims.get("roles", String.class);

        Collection<? extends GrantedAuthority> authorities = Collections.emptyList();
        if (rolesStr != null && !rolesStr.isEmpty()) {
            authorities = Arrays.stream(rolesStr.split(","))
                    .map(String::trim)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
        }

        // username 자리에 email을 넣어도, id를 넣어도 됨
        org.springframework.security.core.userdetails.User principal =
                new org.springframework.security.core.userdetails.User(email, "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public String getJti(String token) {
        Claims claims = parseClaims(token).getBody();
        return claims.getId();
    }

    public long getRemainingValiditySeconds(String token) {
        Claims claims = parseClaims(token).getBody();
        long expMillis = claims.getExpiration().getTime();
        long now = System.currentTimeMillis();
        return Math.max(0, (expMillis - now) / 1000);
    }
}
