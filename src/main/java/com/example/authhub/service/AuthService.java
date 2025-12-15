package com.example.authhub.service;

import com.example.authhub.domain.client.Client;
import com.example.authhub.domain.user.User;
import com.example.authhub.dto.auth.request.LoginRequest;
import com.example.authhub.dto.auth.request.RefreshTokenRequest;
import com.example.authhub.dto.auth.response.LoginResponse;
import com.example.authhub.repository.ClientRepository;
import com.example.authhub.repository.UserRepository;
import com.example.authhub.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenService redisTokenService;

    public LoginResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다."));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("이메일 또는 비밀번호가 올바르지 않습니다.");
        }

        Client client = clientRepository.findByClientId(request.getClientId())
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 clientId 입니다."));

        List<String> roles = Arrays.asList(user.getRoles().split(","));

        String accessToken = jwtTokenProvider.createAccessToken(
                user.getId(),
                user.getEmail(),
                roles
        );

        // Refresh Token은 UUID 문자열로
        String refreshToken = UUID.randomUUID().toString();

        long refreshTtl = client.getRefreshTokenValidity() != null
                ? client.getRefreshTokenValidity()
                : 7 * 24 * 60 * 60; // default 7일

        redisTokenService.storeRefreshToken(refreshToken, user.getId(), client.getClientId(), refreshTtl);

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

    public LoginResponse refresh(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        boolean valid = redisTokenService.validateRefreshToken(refreshToken, request.getClientId());
        if (!valid) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다.");
        }

        Long userId = redisTokenService.getUserIdFromRefreshToken(refreshToken);
        if (userId == null) {
            throw new IllegalArgumentException("유효하지 않은 Refresh Token 입니다.");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("사용자를 찾을 수 없습니다."));

        Client client = clientRepository.findByClientId(request.getClientId())
                .orElseThrow(() -> new IllegalArgumentException("유효하지 않은 clientId 입니다."));

        List<String> roles = Arrays.asList(user.getRoles().split(","));

        String newAccessToken = jwtTokenProvider.createAccessToken(
                user.getId(),
                user.getEmail(),
                roles
        );

        // 회전: 기존 refresh는 삭제 후 새로 발급
        redisTokenService.deleteRefreshToken(refreshToken);

        String newRefreshToken = UUID.randomUUID().toString();
        long refreshTtl = client.getRefreshTokenValidity() != null
                ? client.getRefreshTokenValidity()
                : 7 * 24 * 60 * 60;

        redisTokenService.storeRefreshToken(newRefreshToken, user.getId(), client.getClientId(), refreshTtl);

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

    public void logout(String accessToken, String refreshToken) {
        // Access Token blacklist 등록
        String jti = jwtTokenProvider.getJti(accessToken);
        long ttl = jwtTokenProvider.getRemainingValiditySeconds(accessToken);
        redisTokenService.blacklistAccessToken(jti, ttl);

        // Refresh Token 삭제
        if (refreshToken != null && !refreshToken.isBlank()) {
            redisTokenService.deleteRefreshToken(refreshToken);
        }
    }
}
