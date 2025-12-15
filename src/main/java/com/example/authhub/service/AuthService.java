package com.example.authhub.service;

import com.example.authhub.domain.client.Client;
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
import com.example.authhub.repository.UserRepository;
import com.example.authhub.security.JwtTokenProvider;
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

    /* ==========================
       회원가입
    ========================== */
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

    /* ==========================
       로그인
    ========================== */
    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CREDENTIALS));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }

        Client client = clientRepository.findByClientId(request.getClientId())
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CLIENT));

        List<String> roles = List.of(user.getRole().name());

        String accessToken = jwtTokenProvider.createAccessToken(
                user.getId(),
                user.getEmail(),
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

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(accessTtl)
                .build();
    }

    /* ==========================
       토큰 재발급
    ========================== */
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
                roles
        );

        // Refresh Token 회전
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

    /* ==========================
       로그아웃
    ========================== */
    public void logout(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }

        String accessToken = authorizationHeader.replace("Bearer ", "");

        String jti = jwtTokenProvider.getJti(accessToken);
        long ttl = jwtTokenProvider.getRemainingValiditySeconds(accessToken);
        redisTokenService.blacklistAccessToken(jti, ttl);

        Long userId = jwtTokenProvider.getUserId(accessToken);
        redisTokenService.deleteRefreshTokenByUserId(userId);
    }
}