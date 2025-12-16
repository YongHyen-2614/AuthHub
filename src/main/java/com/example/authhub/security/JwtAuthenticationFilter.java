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

            if (token != null && jwtTokenProvider.validate(token)) {

                // 1) 블랙리스트(jti) 체크
                String jti = jwtTokenProvider.getJti(token);
                if (redisTokenService.isAccessTokenBlacklisted(jti)) {
                    filterChain.doFilter(request, response);
                    return;
                }

                // 2) 강제 로그아웃(logoutAt) 체크
                Long userId = jwtTokenProvider.getUserId(token);
                if (userId != null) {
                    long issuedAtMillis = jwtTokenProvider.getIssuedAtMillis(token);
                    Long logoutAtMillis = redisTokenService.getLogoutAtMillis(userId);

                    boolean forceLoggedOut = (logoutAtMillis != null && issuedAtMillis <= logoutAtMillis);
                    if (!forceLoggedOut) {
                        Authentication authentication = jwtTokenProvider.getAuthentication(token);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
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
