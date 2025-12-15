package com.example.authhub.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.UUID;

@Component
public class JwtTokenProvider {

    private final Key key = Keys.hmacShaKeyFor(
            "very-secret-key-very-secret-key-very-secret-key".getBytes()
    );

    private static final long DEFAULT_ACCESS_TOKEN_EXPIRE_MS = 30 * 60 * 1000; // 30분

    /* =======================
       토큰 검증
       ======================= */
    public boolean validate(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /* =======================
       Access Token 생성
       ======================= */
    public String createAccessToken(Long userId, String email, List<String> roles) {
        long now = System.currentTimeMillis();
        long expiry = now + DEFAULT_ACCESS_TOKEN_EXPIRE_MS;

        return Jwts.builder()
                .setId(UUID.randomUUID().toString()) // jti
                .setSubject(email)
                .claim("userId", userId)
                .claim("roles", roles)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expiry))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    /* =======================
       Claim 추출
       ======================= */
    public String getJti(String token) {
        return parseClaims(token).getId();
    }

    public Long getUserId(String token) {
        Object userId = parseClaims(token).get("userId");
        return userId == null ? null : Long.valueOf(userId.toString());
    }

    /* =======================
       Access Token 남은 TTL (초)
       ======================= */
    public long getRemainingValiditySeconds(String token) {
        Date expiration = parseClaims(token).getExpiration();
        return Math.max(
                (expiration.getTime() - System.currentTimeMillis()) / 1000,
                0
        );
    }

    /* =======================
       JWT → Authentication 변환
       ======================= */
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        String email = claims.getSubject();

        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.get("roles");

        List<GrantedAuthority> authorities = roles.stream()
                .map(role -> (GrantedAuthority) new SimpleGrantedAuthority(role))
                .toList();

        User principal = new User(
                email,
                "",          // 비밀번호 불필요 (이미 JWT로 인증됨)
                authorities
        );

        return new UsernamePasswordAuthenticationToken(
                principal,
                token,
                authorities
        );
    }

    /* =======================
       내부 유틸
       ======================= */
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
