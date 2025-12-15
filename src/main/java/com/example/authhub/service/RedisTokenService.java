package com.example.authhub.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final StringRedisTemplate redisTemplate;

    private String refreshKey(String refreshToken) {
        return "refresh_token:" + refreshToken;
    }

    private String blacklistKey(String jti) {
        return "blacklist:access:" + jti;
    }

    public void storeRefreshToken(String refreshToken, Long userId, String clientId, long ttlSeconds) {
        String key = refreshKey(refreshToken);
        String value = userId + ":" + clientId;
        redisTemplate.opsForValue().set(key, value, Duration.ofSeconds(ttlSeconds));
    }

    public boolean validateRefreshToken(String refreshToken, String clientId) {
        String key = refreshKey(refreshToken);
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) return false;

        // "userId:clientId" 형태라 가정
        String[] parts = value.split(":");
        if (parts.length != 2) return false;

        String storedClientId = parts[1];
        return storedClientId.equals(clientId);
    }

    public Long getUserIdFromRefreshToken(String refreshToken) {
        String key = refreshKey(refreshToken);
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) return null;
        String[] parts = value.split(":");
        if (parts.length != 2) return null;
        return Long.valueOf(parts[0]);
    }

    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(refreshKey(refreshToken));
    }

    public void blacklistAccessToken(String jti, long ttlSeconds) {
        redisTemplate.opsForValue().set(
                blacklistKey(jti),
                "true",
                Duration.ofSeconds(ttlSeconds)
        );
    }

    public boolean isAccessTokenBlacklisted(String jti) {
        String value = redisTemplate.opsForValue().get(blacklistKey(jti));
        return value != null;
    }
}
