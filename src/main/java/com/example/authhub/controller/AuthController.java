package com.example.authhub.controller;

import com.example.authhub.dto.auth.request.LoginRequest;
import com.example.authhub.dto.auth.request.LogoutRequest;
import com.example.authhub.dto.auth.request.RefreshTokenRequest;
import com.example.authhub.dto.auth.request.SignupRequest;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.dto.auth.response.LoginResponse;
import com.example.authhub.service.AuthService;
import com.example.authhub.success.SuccessCode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse<Void>> signup(@Valid @RequestBody SignupRequest request) {
        authService.signup(request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.SIGNUP_SUCCESS.getCode(),
                        SuccessCode.SIGNUP_SUCCESS.getMessage()
                )
        );
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.LOGIN_SUCCESS.getCode(),
                        SuccessCode.LOGIN_SUCCESS.getMessage(),
                        response
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        LoginResponse response = authService.refresh(request);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.TOKEN_REFRESH_SUCCESS.getCode(),
                        SuccessCode.TOKEN_REFRESH_SUCCESS.getMessage(),
                        response
                )
        );
    }

    /**
     * 로그아웃(기본): 현재 기기(clientId)만 로그아웃
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        authService.logout(authorizationHeader);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.LOGOUT_SUCCESS.getCode(),
                        SuccessCode.LOGOUT_SUCCESS.getMessage()
                )
        );
    }

    /**
     * 로그아웃(전체): 모든 기기 로그아웃 [
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAll(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        authService.logoutAll(authorizationHeader);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.LOGOUT_SUCCESS.getCode(),
                        SuccessCode.LOGOUT_SUCCESS.getMessage()
                )
        );
    }
}
