package com.example.authhub.security;

import com.example.authhub.service.auth.RedisTokenService;
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

            if (token != null && jwtTokenProvider.validate(token)) {

                String jti = jwtTokenProvider.getJti(token);
                if (redisTokenService.isAccessTokenBlacklisted(jti)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                Long userId = jwtTokenProvider.getUserId(token);
                String clientId = jwtTokenProvider.getClientId(token);
                long issuedAtMillis = jwtTokenProvider.getIssuedAtMillis(token);

                // 전체 강제 로그아웃 체크
                if (userId != null) {
                    Long logoutAt = redisTokenService.getLogoutAtMillis(userId);
                    if (logoutAt != null && issuedAtMillis <= logoutAt) {
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                // client별 강제 로그아웃 체크 (clientId가 토큰에 있을 때만)
                if (userId != null && clientId != null) {
                    Long logoutAtClient = redisTokenService.getClientLogoutAtMillis(userId, clientId);
                    if (logoutAtClient != null && issuedAtMillis <= logoutAtClient) {
                        filterChain.doFilter(request, response);
                        return;
                    }
                }

                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

            filterChain.doFilter(request, response);
        } finally {
            SecurityContextHolder.clearContext();
        }
    }

    private String resolveToken(HttpServletRequest request) {
        String bearer = request.getHeader("Authorization");
        if (bearer != null && bearer.startsWith("Bearer ")) {
            return bearer.substring(7);
        }
        return null;
    }
}
