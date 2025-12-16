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
    private static final String USER_CLIENT_PREFIX = "user_client:";

    /* =================================================
       Refresh Token 저장 (로그인 시)
       ================================================= */
    public void storeRefreshToken(
            String refreshToken,
            Long userId,
            String clientId,
            long ttlSeconds
    ) {
        String refreshKey = REFRESH_PREFIX + refreshToken;
        String indexKey = USER_CLIENT_PREFIX + userId + ":" + clientId;

        // refresh:{token} -> userId:clientId
        redisTemplate.opsForValue()
                .set(refreshKey, userId + ":" + clientId, ttlSeconds, TimeUnit.SECONDS);

        // user_client:{userId}:{clientId} -> refreshToken
        redisTemplate.opsForValue()
                .set(indexKey, refreshToken, ttlSeconds, TimeUnit.SECONDS);
    }

    /* =================================================
       중복 로그인 체크
       ================================================= */
    public boolean isAlreadyLoggedIn(Long userId, String clientId) {
        String indexKey = USER_CLIENT_PREFIX + userId + ":" + clientId;
        return Boolean.TRUE.equals(redisTemplate.hasKey(indexKey));
    }

    /* =================================================
       Refresh Token 검증
       ================================================= */
    public boolean validateRefreshToken(String refreshToken, String clientId) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return false;

        String[] parts = value.split(":");
        return parts.length == 2 && parts[1].equals(clientId);
    }

    /* =================================================
       Refresh Token → userId 추출
       ================================================= */
    public Long getUserIdFromRefreshToken(String refreshToken) {
        String value = redisTemplate.opsForValue()
                .get(REFRESH_PREFIX + refreshToken);

        if (value == null) return null;

        return Long.parseLong(value.split(":")[0]);
    }

    /* =================================================
       Refresh Token 단건 삭제 (회전/로그아웃)
       ================================================= */
    public void deleteRefreshToken(String refreshToken) {
        redisTemplate.delete(REFRESH_PREFIX + refreshToken);
    }

    /* =================================================
       로그아웃 / 세션 만료 시
       해당 유저의 모든 세션 제거
       ================================================= */
    public void deleteAllSessionsByUser(Long userId) {
        String pattern = USER_CLIENT_PREFIX + userId + ":*";

        redisTemplate.keys(pattern).forEach(indexKey -> {
            String refreshToken = redisTemplate.opsForValue().get(indexKey);
            if (refreshToken != null) {
                redisTemplate.delete(REFRESH_PREFIX + refreshToken);
            }
            redisTemplate.delete(indexKey);
        });
    }

    /* =================================================
       Access Token 블랙리스트
       ================================================= */
    public void blacklistAccessToken(String jti, long ttlSeconds) {
        redisTemplate.opsForValue()
                .set(
                        ACCESS_BLACKLIST_PREFIX + jti,
                        "true",
                        ttlSeconds,
                        TimeUnit.SECONDS
                );
    }

    public boolean isAccessTokenBlacklisted(String jti) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(ACCESS_BLACKLIST_PREFIX + jti)
        );
    }
}
