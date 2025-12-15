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
    private static final String ACCESS_BLACKLIST_PREFIX = "blacklist:access:";

    /* Refresh Token 저장 */
    public void storeRefreshToken(String refreshToken,
                                  Long userId,
                                  String clientId,
                                  long ttlSeconds) {

        String key = REFRESH_PREFIX + refreshToken;
        String value = userId + ":" + clientId;

        redisTemplate.opsForValue()
                .set(key, value, ttlSeconds, TimeUnit.SECONDS);
    }

    /* Refresh Token 검증 */
    public boolean validateRefreshToken(String refreshToken, String clientId) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return false;

        String[] parts = value.split(":");
        return parts.length == 2 && parts[1].equals(clientId);
    }

    /* Refresh Token → userId 추출 */
    public Long getUserIdFromRefreshToken(String refreshToken) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return null;

        return Long.parseLong(value.split(":")[0]);
    }

    /* Refresh Token 삭제 */
    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(REFRESH_PREFIX + refreshToken);
    }

    /* ===== Access Token Blacklist ===== */

    public void blacklistAccessToken(String jti, long ttlSeconds) {
        redisTemplate.opsForValue()
                .set(ACCESS_BLACKLIST_PREFIX + jti, "true", ttlSeconds, TimeUnit.SECONDS);
    }

    public void deleteRefreshTokenByUserId(Long userId) {
        String pattern = "refresh:*";

        redisTemplate.keys(pattern).forEach(key -> {
            String value = redisTemplate.opsForValue().get(key);
            if (value != null && value.startsWith(userId + ":")) {
                redisTemplate.delete(key);
            }
        });
    }

    public boolean isAccessTokenBlacklisted(String jti) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(ACCESS_BLACKLIST_PREFIX + jti)
        );
    }
}
