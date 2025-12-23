package com.example.authhub.controller.admin;

import com.example.authhub.security.JwtTokenProvider;
import com.example.authhub.service.auth.RedisTokenService;
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

    /**
     * 관리자 강제 로그아웃(전체): 특정 userId의 모든 기기 세션을 무효화한다.
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Path: /admin/users/{userId}/force-logout
     *
     * [정책]
     * 1) userId에 연결된 모든 refresh 세션을 삭제한다.
     * 2) logoutAt(user scope)을 기록하여, 과거에 발급된 access token도 서버에서 거부되도록 한다.
     * 3) TTL은 accessTokenValiditySeconds + buffer(예: 60초) 범위로 유지한다.
     *
     * [응답]
     * - ResponseEntity<Void> (204 No Content)
     *
     * [주의]
     * - 운영에서 영향이 크므로 감사 로그(LoginHistory 등)와 함께 사용하는 것을 권장한다.
     */
    @PostMapping("/users/{userId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> forceLogoutAll(@PathVariable Long userId) {
        redisTokenService.forceLogoutAll(userId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.noContent().build();
    }

    /**
     * 관리자 강제 로그아웃(단일 클라이언트): 특정 userId의 특정 clientId만 무효화한다.
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Path: /admin/users/{userId}/clients/{clientId}/force-logout
     *
     * [정책]
     * 1) (userId, clientId) refresh 세션만 삭제한다.
     * 2) logoutAt(client scope)을 기록하여, 해당 clientId로 과거 발급된 access token도 서버에서 거부되도록 한다.
     *
     * [응답]
     * - ResponseEntity<Void> (204 No Content)
     */
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
