package com.example.authhub.controller.auth;

import com.example.authhub.dto.auth.request.LoginRequest;
import com.example.authhub.dto.auth.request.RefreshTokenRequest;
import com.example.authhub.dto.auth.request.SignupRequest;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.dto.auth.response.LoginResponse;
import com.example.authhub.dto.auth.response.MeResponse;
import com.example.authhub.service.auth.AuthService;
import com.example.authhub.service.auth.MeService;
import com.example.authhub.success.SuccessCode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final MeService meService;

    /**
     * 회원가입
     *
     * [인증]
     * - 인증 불필요 (permitAll)
     *
     * [요청]
     * - Body: SignupRequest(email, password, ...)
     *
     * [정책]
     * - 이메일 중복 시 EMAIL_ALREADY_EXISTS(A001) 발생
     * - 비밀번호는 PasswordEncoder로 해시 저장
     *
     * [응답]
     * - ApiResponse<Void>
     * - SuccessCode: SIGNUP_SUCCESS
     */
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

    /**
     * 로그인
     *
     * [인증]
     * - 인증 불필요 (permitAll)
     *
     * [요청]
     * - Body: LoginRequest(email, password, clientId)
     *
     * [정책]
     * - 사용자/비밀번호 불일치 시 INVALID_CREDENTIALS(A002)
     * - clientId 유효하지 않으면 INVALID_CLIENT(A006)
     * - 중복 로그인 방지 정책이 활성화된 경우 ALREADY_LOGGED_IN(A008)
     * - AccessToken(JWT) + RefreshToken(UUID) 발급
     * - RefreshToken은 Redis에 저장되며 TTL은 Client 설정(refreshTokenValidity)을 따른다.
     *
     * [응답]
     * - ApiResponse<LoginResponse>
     * - data: accessToken, refreshToken, tokenType, expiresIn
     * - SuccessCode: LOGIN_SUCCESS
     */
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

    /**
     * 토큰 재발급 (Refresh / Rotation)
     *
     * [인증]
     * - 인증 불필요 (permitAll)
     * - 다만 RefreshToken이 유효해야 한다.
     *
     * [요청]
     * - Body: RefreshTokenRequest(refreshToken, clientId)
     *
     * [정책]
     * - RefreshToken 검증 실패 시 INVALID_REFRESH_TOKEN(A004)
     * - RefreshToken Rotation: 기존 refresh 삭제 후 새 refresh 발급/저장
     * - AccessToken은 새로 발급된다.
     *
     * [응답]
     * - ApiResponse<LoginResponse>
     * - SuccessCode: TOKEN_REFRESH_SUCCESS
     */
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
     *
     * [인증]
     * - Authorization: Bearer {accessToken} 필요
     *
     * [요청]
     * - Header: Authorization
     *
     * [정책]
     * 1) 현재 access token(jti)을 블랙리스트 처리하여 즉시 무효화한다.
     * 2) (userId, clientId)에 해당하는 refresh 세션만 삭제한다.
     * 3) logoutAt(client scope)을 기록하여, 과거에 발급된 access token도 서버에서 거부되도록 한다.
     *
     * [응답]
     * - ApiResponse<Void>
     * - SuccessCode: LOGOUT_SUCCESS
     *
     * [주의]
     * - Stateless 구조이므로 “토큰 폐기”는 Redis 정책(블랙리스트/logoutAt)에 의해 서버에서 거부되는 방식이다.
     */
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestHeader("Authorization") String authorizationHeader) {
        authService.logout(authorizationHeader);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.LOGOUT_SUCCESS.getCode(),
                        SuccessCode.LOGOUT_SUCCESS.getMessage()
                )
        );
    }

    /**
     * 로그아웃(전체): 모든 기기 로그아웃
     *
     * [인증]
     * - Authorization: Bearer {accessToken} 필요
     *
     * [요청]
     * - Header: Authorization
     *
     * [정책]
     * 1) 현재 access token(jti)을 블랙리스트 처리하여 즉시 무효화한다.
     * 2) userId에 연결된 모든 refresh 세션을 삭제한다.
     * 3) logoutAt(user scope)을 기록하여, 과거에 발급된 access token도 서버에서 거부되도록 한다.
     *
     * [응답]
     * - ApiResponse<Void>
     * - SuccessCode: LOGOUT_SUCCESS (프로젝트 정책에 따라 별도 성공코드로 분리 가능)
     *
     * [주의]
     * - 운영에서 영향 범위가 크므로, 사용자 본인 요청 또는 관리자 승인 플로우로 제한하는 것을 권장한다.
     */
    @PostMapping("/logout-all")
    public ResponseEntity<ApiResponse<Void>> logoutAll(@RequestHeader("Authorization") String authorizationHeader) {
        authService.logoutAll(authorizationHeader);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.LOGOUT_SUCCESS.getCode(),
                        SuccessCode.LOGOUT_SUCCESS.getMessage()
                )
        );
    }

    /**
     * 내 정보 조회
     *
     * [인증]
     * - Authorization: Bearer {accessToken} 필요
     *
     * [요청]
     * - Header: Authorization
     *
     * [반환]
     * - userId, email, clientId, roles
     * - roles는 "ROLE_ADMIN" 형식으로 반환된다.
     *
     * [응답]
     * - ApiResponse<MeResponse>
     * - SuccessCode: ME_SUCCESS
     *
     * [주의]
     * - 기본 구현은 SecurityContext/JWT 기반이다.
     * - 사용자 프로필(닉네임 등) 확장은 MeService에서 DB 조회를 추가하는 방식으로 확장한다.
     */
    @GetMapping("/me")
    public ResponseEntity<ApiResponse<MeResponse>> me() {
        MeResponse meResponse = meService.me();
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ME_SUCCESS.getCode(),
                        SuccessCode.ME_SUCCESS.getMessage(),
                        meResponse
                )
        );
    }
}
