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
     * 전체 기기 강제 로그아웃
     * POST /admin/users/{userId}/force-logout
     */
    @PostMapping("/users/{userId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> forceLogoutAll(@PathVariable Long userId) {

        redisTokenService.forceLogoutAll(
                userId,
                jwtTokenProvider.getAccessTokenValiditySeconds()
        );

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.FORCE_LOGOUT_SUCCESS.getCode(),
                        SuccessCode.FORCE_LOGOUT_SUCCESS.getMessage()
                )
        );
    }

    /**
     * 특정 clientId만 강제 로그아웃
     * POST /admin/users/{userId}/clients/{clientId}/force-logout
     */
    @PostMapping("/users/{userId}/clients/{clientId}/force-logout")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> forceLogoutClient(
            @PathVariable Long userId,
            @PathVariable String clientId
    ) {

        redisTokenService.forceLogoutClient(
                userId,
                clientId,
                jwtTokenProvider.getAccessTokenValiditySeconds()
        );

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.FORCE_LOGOUT_SUCCESS.getCode(),
                        SuccessCode.FORCE_LOGOUT_SUCCESS.getMessage()
                )
        );
    }
}
