package com.example.authhub.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisTokenService {

    private final StringRedisTemplate redisTemplate;

    private static final String REFRESH_PREFIX = "refresh:";
    private static final String ACCESS_BLACKLIST_PREFIX = "blacklist:access:";
    private static final String USER_CLIENT_PREFIX = "user_client:";
    private static final String LOGOUT_AT_PREFIX = "logout_at:"; // logout_at:{userId} or logout_at:{userId}:{clientId}

    public void storeRefreshToken(String refreshToken, Long userId, String clientId, long ttlSeconds) {
        String refreshKey = REFRESH_PREFIX + refreshToken;
        String indexKey = USER_CLIENT_PREFIX + userId + ":" + clientId;

        // refresh:{token} -> userId:clientId
        redisTemplate.opsForValue()
                .set(refreshKey, userId + ":" + clientId, ttlSeconds, TimeUnit.SECONDS);

        // user_client:{userId}:{clientId} -> refreshToken
        redisTemplate.opsForValue()
                .set(indexKey, refreshToken, ttlSeconds, TimeUnit.SECONDS);
    }

    public boolean isAlreadyLoggedIn(Long userId, String clientId) {
        String indexKey = USER_CLIENT_PREFIX + userId + ":" + clientId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(indexKey));
    }

    public boolean validateRefreshToken(String refreshToken, String clientId) {
        String value = redisTemplate.opsForValue().get(REFRESH_PREFIX + refreshToken);
        if (value == null) return false;

        String[] parts = value.split(":");
        return parts.length == 2 && parts[1].equals(clientId);
    }

    public Long getUserIdFromRefreshToken(String refreshToken) {
        String value = redisTemplate.opsForValue().get(REFRESH_PREFIX + refreshToken);
        if (value == null) return null;

        return Long.parseLong(value.split(":")[0]);
    }

    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(REFRESH_PREFIX + refreshToken);
    }

    /**
     * userId의 모든 client 세션 삭제
     * (운영에서 keys(pattern) 비용 이슈는 나중에 개선)
     */
    public void deleteAllSessionsByUser(Long userId) {
        String pattern = USER_CLIENT_PREFIX + userId + ":*";

        Set<String> keys = redisTemplate.keys(pattern);
        if (keys == null || keys.isEmpty()) return;

        for (String indexKey : keys) {
            String refreshToken = redisTemplate.opsForValue().get(indexKey);
            if (refreshToken != null) {
                redisTemplate.delete(REFRESH_PREFIX + refreshToken);
            }
            redisTemplate.delete(indexKey);
        }
    }

    /**
     * 특정 client 세션만 삭제
     */
    public void deleteSessionByUserAndClient(Long userId, String clientId) {
        String indexKey = USER_CLIENT_PREFIX + userId + ":" + clientId;
        String refreshToken = redisTemplate.opsForValue().get(indexKey);

        if (refreshToken != null) {
            redisTemplate.delete(REFRESH_PREFIX + refreshToken);
        }
        redisTemplate.delete(indexKey);
    }

    public void blacklistAccessToken(String jti, long ttlSeconds) {
        redisTemplate.opsForValue()
                .set(ACCESS_BLACKLIST_PREFIX + jti, "true", ttlSeconds, TimeUnit.SECONDS);
    }

    public boolean isAccessTokenBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(ACCESS_BLACKLIST_PREFIX + jti));
    }

    // ===== logoutAt (전체) =====

    public void setLogoutAtMillis(Long userId, long logoutAtMillis, long ttlSeconds) {
        redisTemplate.opsForValue().set(
                LOGOUT_AT_PREFIX + userId,
                String.valueOf(logoutAtMillis),
                ttlSeconds,
                TimeUnit.SECONDS
        );
    }

    public Long getLogoutAtMillis(Long userId) {
        String v = redisTemplate.opsForValue().get(LOGOUT_AT_PREFIX + userId);
        return (v == null) ? null : Long.parseLong(v);
    }

    // ===== logoutAt (client별) =====

    public void setClientLogoutAtMillis(Long userId, String clientId, long logoutAtMillis, long ttlSeconds) {
        redisTemplate.opsForValue().set(
                LOGOUT_AT_PREFIX + userId + ":" + clientId,
                String.valueOf(logoutAtMillis),
                ttlSeconds,
                TimeUnit.SECONDS
        );
    }

    public Long getClientLogoutAtMillis(Long userId, String clientId) {
        String v = redisTemplate.opsForValue().get(LOGOUT_AT_PREFIX + userId + ":" + clientId);
        return (v == null) ? null : Long.parseLong(v);
    }

    /**
     * 전체 강제 로그아웃:
     * - refresh 세션 전부 삭제 + logout_at:{userId} 갱신
     */
    public void forceLogoutAll(Long userId, long accessTokenValiditySeconds) {
        deleteAllSessionsByUser(userId);
        long now = System.currentTimeMillis();
        setLogoutAtMillis(userId, now, accessTokenValiditySeconds + 60);
    }

    /**
     * client별 강제 로그아웃:
     * - 해당 client 세션만 삭제 + logout_at:{userId}:{clientId} 갱신
     */
    public void forceLogoutClient(Long userId, String clientId, long accessTokenValiditySeconds) {
        deleteSessionByUserAndClient(userId, clientId);
        long now = System.currentTimeMillis();
        setClientLogoutAtMillis(userId, clientId, now, accessTokenValiditySeconds + 60);
    }
}
