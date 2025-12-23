package com.example.authhub.service.auth;

import com.example.authhub.dto.auth.response.MeResponse;
import com.example.authhub.exception.AuthException;
import com.example.authhub.exception.ErrorCode;
import com.example.authhub.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MeService {

    private final JwtTokenProvider jwtTokenProvider;

    public MeResponse me() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }

        Object credentials = authentication.getCredentials();
        if (!(credentials instanceof String token) || token.isBlank()) {
            throw new AuthException(ErrorCode.UNAUTHORIZED);
        }

        Long userId = jwtTokenProvider.getUserId(token);
        String clientId = jwtTokenProvider.getClientId(token);

        String email;
        Object principal = authentication.getPrincipal();
        if (principal instanceof org.springframework.security.core.userdetails.User u) {
            email = u.getUsername();
        } else if (principal instanceof String s) {
            email = s;
        } else {
            email = null;
        }

        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return MeResponse.builder()
                .userId(userId)
                .email(email)
                .clientId(clientId)
                .roles(roles)
                .build();
    }
}
