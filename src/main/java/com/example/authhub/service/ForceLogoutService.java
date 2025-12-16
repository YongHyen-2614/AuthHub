package com.example.authhub.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ForceLogoutService {

    private final StringRedisTemplate redis;

    private static String rtKey(Long userId) { return "RT:" + userId; }
    private static String logoutAtKey(Long userId) { return "LOGOUT_AT:" + userId; }

    public void forceLogoutAll(Long userId) {
        // 1) refresh token 제거 (재발급 차단)
        redis.delete(rtKey(userId));

        // 2) 기존 access token 전부 무효화 기준 저장
        redis.opsForValue().set(logoutAtKey(userId), String.valueOf(System.currentTimeMillis()));
    }
}
