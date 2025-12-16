package com.example.authhub.controller;

import com.example.authhub.security.JwtTokenProvider;
import com.example.authhub.service.RedisTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin")
public class AdminForceLogoutController {

    private final RedisTokenService redisTokenService;
    private final JwtTokenProvider jwtTokenProvider;

    @PostMapping("/users/{userId}/force-logout")
    public ResponseEntity<Void> forceLogout(@PathVariable Long userId) {
        redisTokenService.forceLogoutAll(userId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.noContent().build();
    }
}
