package com.example.authhub.service.auth;

import com.example.authhub.domain.client.Client;
import com.example.authhub.domain.login.LoginHistory;
import com.example.authhub.domain.user.AuthProvider;
import com.example.authhub.domain.user.Role;
import com.example.authhub.domain.user.User;
import com.example.authhub.dto.auth.request.LoginRequest;
import com.example.authhub.dto.auth.request.RefreshTokenRequest;
import com.example.authhub.dto.auth.request.SignupRequest;
import com.example.authhub.dto.auth.response.LoginResponse;
import com.example.authhub.exception.AuthException;
import com.example.authhub.exception.ErrorCode;
import com.example.authhub.repository.ClientRepository;
import com.example.authhub.repository.LoginHistoryRepository;
import com.example.authhub.repository.UserRepository;
import com.example.authhub.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenService redisTokenService;

    private final LoginHistoryRepository loginHistoryRepository;

    public void signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .role(Role.ROLE_USER)
                .enabled(true)
                .build();

        userRepository.save(user);
    }

    /**
     * 로그인(로그인 이력 저장 포함)
     * - 성공 시: success=true 기록
     * - 실패 시: success=false + reason 기록 후 예외 발생
     */
    public LoginResponse login(LoginRequest request, HttpServletRequest httpRequest) {

        String email = request.getEmail();
        String clientId = request.getClientId();
        String ip = extractClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> {
                        saveLoginFail(email, clientId, ip, userAgent, "INVALID_CREDENTIALS");
                        return new AuthException(ErrorCode.INVALID_CREDENTIALS);
                    });

            if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
                saveLoginFail(email, clientId, ip, userAgent, "INVALID_CREDENTIALS");
                throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
            }

            Client client = clientRepository.findByClientId(clientId)
                    .orElseThrow(() -> {
                        saveLoginFail(email, clientId, ip, userAgent, "INVALID_CLIENT");
                        return new AuthException(ErrorCode.INVALID_CLIENT);
                    });

            if (redisTokenService.isAlreadyLoggedIn(user.getId(), client.getClientId())) {
                saveLoginFail(email, clientId, ip, userAgent, "ALREADY_LOGGED_IN");
                throw new AuthException(ErrorCode.ALREADY_LOGGED_IN);
            }

            List<String> roles = List.of(user.getRole().name());

            String accessToken = jwtTokenProvider.createAccessToken(
                    user.getId(),
                    user.getEmail(),
                    client.getClientId(),
                    roles
            );

            String refreshToken = UUID.randomUUID().toString();

            long refreshTtl = client.getRefreshTokenValidity() != null
                    ? client.getRefreshTokenValidity()
                    : 7 * 24 * 60 * 60;

            redisTokenService.storeRefreshToken(
                    refreshToken,
                    user.getId(),
                    client.getClientId(),
                    refreshTtl
            );

            long accessTtl = client.getAccessTokenValidity() != null
                    ? client.getAccessTokenValidity()
                    : jwtTokenProvider.getRemainingValiditySeconds(accessToken);

            saveLoginSuccess(user.getId(), email, clientId, ip, userAgent);

            return LoginResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(accessTtl)
                    .build();

        } catch (AuthException e) {
            throw e;
        }
    }

    /**
     * 기존 시그니처를 호출하는 코드가 남아있을 수 있어 보조로 유지하고 싶다면 사용
     * - Controller를 모두 수정했다면 이 메서드는 삭제해도 됨
     */
    public LoginResponse login(LoginRequest request) {
        throw new UnsupportedOperationException("Use login(LoginRequest, HttpServletRequest)");
    }

    public LoginResponse refresh(RefreshTokenRequest request) {

        if (!redisTokenService.validateRefreshToken(request.getRefreshToken(), request.getClientId())) {
            throw new AuthException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        Long userId = redisTokenService.getUserIdFromRefreshToken(request.getRefreshToken());
        if (userId == null) {
            throw new AuthException(ErrorCode.INVALID_REFRESH_TOKEN);
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        Client client = clientRepository.findByClientId(request.getClientId())
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CLIENT));

        List<String> roles = List.of(user.getRole().name());

        String newAccessToken = jwtTokenProvider.createAccessToken(
                user.getId(),
                user.getEmail(),
                client.getClientId(),
                roles
        );

        redisTokenService.deleteRefreshToken(request.getRefreshToken());

        String newRefreshToken = UUID.randomUUID().toString();

        long refreshTtl = client.getRefreshTokenValidity() != null
                ? client.getRefreshTokenValidity()
                : 7 * 24 * 60 * 60;

        redisTokenService.storeRefreshToken(
                newRefreshToken,
                user.getId(),
                client.getClientId(),
                refreshTtl
        );

        long accessTtl = client.getAccessTokenValidity() != null
                ? client.getAccessTokenValidity()
                : jwtTokenProvider.getRemainingValiditySeconds(newAccessToken);

        return LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTtl)
                .build();
    }

    /**
     * 로그아웃(기본): 현재 기기(clientId)만 로그아웃
     * - 현재 access token(jti) 블랙리스트
     * - (userId, clientId)의 refresh 세션만 삭제
     * - 해당 clientId에 logoutAt 설정하여 기존 access 토큰도 무효화
     */
    public void logout(String authorizationHeader) {

        String accessToken = extractBearerToken(authorizationHeader);

        String jti = jwtTokenProvider.getJti(accessToken);
        long ttl = jwtTokenProvider.getRemainingValiditySeconds(accessToken);
        redisTokenService.blacklistAccessToken(jti, ttl);

        Long userId = jwtTokenProvider.getUserId(accessToken);
        String clientId = jwtTokenProvider.getClientId(accessToken);

        if (userId == null || clientId == null) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }

        redisTokenService.deleteSessionByUserAndClient(userId, clientId);

        redisTokenService.forceLogoutClient(
                userId,
                clientId,
                jwtTokenProvider.getAccessTokenValiditySeconds()
        );
    }

    /**
     * 로그아웃(전체): 모든 기기 로그아웃
     * - 현재 access token(jti) 블랙리스트
     * - userId의 모든 refresh 세션 삭제
     * - userId 전체 logoutAt 설정하여 기존 access 토큰도 무효화
     */
    public void logoutAll(String authorizationHeader) {

        String accessToken = extractBearerToken(authorizationHeader);

        String jti = jwtTokenProvider.getJti(accessToken);
        long ttl = jwtTokenProvider.getRemainingValiditySeconds(accessToken);
        redisTokenService.blacklistAccessToken(jti, ttl);

        Long userId = jwtTokenProvider.getUserId(accessToken);
        if (userId == null) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }

        redisTokenService.forceLogoutAll(
                userId,
                jwtTokenProvider.getAccessTokenValiditySeconds()
        );
    }

    private String extractBearerToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }
        return authorizationHeader.substring(7);
    }

    // ===== 로그인 이력 저장 유틸 =====

    private void saveLoginSuccess(Long userId, String email, String clientId, String ip, String userAgent) {
        try {
            loginHistoryRepository.save(LoginHistory.success(userId, email, clientId, ip, userAgent));
        } catch (Exception ignore) {
        }
    }

    private void saveLoginFail(String email, String clientId, String ip, String userAgent, String reason) {
        try {
            loginHistoryRepository.save(LoginHistory.fail(email, clientId, ip, userAgent, reason));
        } catch (Exception ignore) {
        }
    }

    private String extractClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
