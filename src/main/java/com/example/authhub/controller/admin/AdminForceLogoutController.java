package com.example.authhub.controller.admin;

import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.security.JwtTokenProvider;
import com.example.authhub.service.auth.RedisTokenService;
import com.example.authhub.success.SuccessCode;
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
     * 관리자 강제 로그아웃(전체): 특정 userId의 모든 기기 세션 무효화
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Path: userId
     * [정책] refresh 세션 전체 삭제 + logoutAt(user) 기록
     * [응답] ApiResponse<Void>
     * - SuccessCode: ADMIN_FORCE_LOGOUT_ALL_SUCCESS
     */
    @PostMapping("/users/{userId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> forceLogoutAll(@PathVariable Long userId) {
        redisTokenService.forceLogoutAll(userId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_FORCE_LOGOUT_ALL_SUCCESS.getCode(),
                        SuccessCode.ADMIN_FORCE_LOGOUT_ALL_SUCCESS.getMessage()
                )
        );
    }

    /**
     * 관리자 강제 로그아웃(단일 클라이언트): 특정 userId의 특정 clientId만 무효화
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Path: userId, clientId
     * [정책] refresh 세션(client) 삭제 + logoutAt(client) 기록
     * [응답] ApiResponse<Void>
     * - SuccessCode: ADMIN_FORCE_LOGOUT_CLIENT_SUCCESS
     */
    @PostMapping("/users/{userId}/clients/{clientId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> forceLogoutClient(
            @PathVariable Long userId,
            @PathVariable String clientId
    ) {
        redisTokenService.forceLogoutClient(userId, clientId, jwtTokenProvider.getAccessTokenValiditySeconds());
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_FORCE_LOGOUT_CLIENT_SUCCESS.getCode(),
                        SuccessCode.ADMIN_FORCE_LOGOUT_CLIENT_SUCCESS.getMessage()
                )
        );
    }
}
