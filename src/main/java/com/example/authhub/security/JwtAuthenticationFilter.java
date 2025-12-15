package com.example.authhub.security;

import com.example.authhub.service.RedisTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RedisTokenService redisTokenService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        try {
            String token = resolveToken(request);

            // 토큰 존재 + 구조적 유효성 검증
            if (token != null && jwtTokenProvider.validate(token)) {

                // Access Token 블랙리스트 확인
                String jti = jwtTokenProvider.getJti(token);
                boolean isBlacklisted =
                        redisTokenService.isAccessTokenBlacklisted(jti);

                if (!isBlacklisted) {
                    // 인증 객체 생성
                    Authentication authentication =
                            jwtTokenProvider.getAuthentication(token);

                    // SecurityContext에 인증 정보 저장
                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication);
                }
            }

            // 다음 필터 진행
            filterChain.doFilter(request, response);

        } finally {
            // 요청 종료 시 SecurityContext 정리 (중요)
            SecurityContextHolder.clearContext();
        }
    }

    /**
     * Authorization Header에서 Bearer 토큰 추출
     */
    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
