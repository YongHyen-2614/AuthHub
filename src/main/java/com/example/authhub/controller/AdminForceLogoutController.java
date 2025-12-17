package com.example.authhub.controller;

import com.example.authhub.security.JwtTokenProvider;
import com.example.authhub.service.RedisTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
public class AdminForceLogoutController {

    private final RedisTokenService redisTokenService;
    private final JwtTokenProvider jwtTokenProvider;

    // 전체 기기 강제 로그아웃
    @PostMapping("/users/{userId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> forceLogoutAll(@PathVariable Long userId) {
        redisTokenService.forceLogoutAll(userId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.noContent().build();
    }

    // 특정 clientId만 강제 로그아웃
    @PostMapping("/users/{userId}/clients/{clientId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> forceLogoutClient(
            @PathVariable Long userId,
            @PathVariable String clientId
    ) {
        redisTokenService.forceLogoutClient(userId, clientId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.noContent().build();
    }
}
