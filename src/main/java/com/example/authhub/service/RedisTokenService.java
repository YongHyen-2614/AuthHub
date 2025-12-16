package com.example.authhub.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final StringRedisTemplate redisTemplate;

    private static final String REFRESH_PREFIX = "refresh:";
    private static final String USER_CLIENT_PREFIX = "user_client:";
    private static final String ACCESS_BLACKLIST_PREFIX = "blacklist:access:";

    /* ==========================
       Refresh Token 저장
    ========================== */
    public void storeRefreshToken(
            String refreshToken,
            Long userId,
            String clientId,
            long ttl
    ) {
        String tokenKey = "refresh:" + refreshToken;
        String indexKey = "user_client:" + userId + ":" + clientId;

        // refreshToken → userId:clientId
        redisTemplate.opsForValue()
                .set(tokenKey, userId + ":" + clientId, ttl, TimeUnit.SECONDS);

        // user+client → refreshToken (중복 로그인 제어용)
        redisTemplate.opsForValue()
                .set(indexKey, refreshToken, ttl, TimeUnit.SECONDS);
    }
    /* ==========================
       중복 로그인 제거
    ========================== */
    public void deleteExistingSession(Long userId, String clientId) {
        String indexKey = "user_client:" + userId + ":" + clientId;

        String existingRefreshToken =
                redisTemplate.opsForValue().get(indexKey);

        if (existingRefreshToken != null) {
            // 기존 Refresh Token 삭제
            redisTemplate.delete("refresh:" + existingRefreshToken);

            // 인덱스 삭제
            redisTemplate.delete(indexKey);
        }
    }

    /* ==========================
       Refresh Token 검증
    ========================== */
    public boolean validateRefreshToken(String refreshToken, String clientId) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return false;

        String[] parts = value.split(":");
        return parts.length == 2 && parts[1].equals(clientId);
    }

    public Long getUserIdFromRefreshToken(String refreshToken) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return null;

        return Long.parseLong(value.split(":")[0]);
    }

    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(REFRESH_PREFIX + refreshToken);
    }

    public void deleteAllSessionsByUser(Long userId) {
        String pattern = "user_client:" + userId + ":*";

        redisTemplate.keys(pattern).forEach(indexKey -> {
            String refreshToken = redisTemplate.opsForValue().get(indexKey);
            if (refreshToken != null) {
                redisTemplate.delete("refresh:" + refreshToken);
            }
            redisTemplate.delete(indexKey);
        });
    }

    /* ==========================
       Access Token Blacklist
    ========================== */
    public void blacklistAccessToken(String jti, long ttlSeconds) {
        redisTemplate.opsForValue()
                .set(ACCESS_BLACKLIST_PREFIX + jti, "true", ttlSeconds, TimeUnit.SECONDS);
    }

    public boolean isAccessTokenBlacklisted(String jti) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(ACCESS_BLACKLIST_PREFIX + jti)
        );
    }
}