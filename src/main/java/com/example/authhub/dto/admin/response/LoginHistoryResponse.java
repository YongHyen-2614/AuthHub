package com.example.authhub.dto.admin.response;

import com.example.authhub.domain.login.LoginHistory;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class LoginHistoryResponse {
    private Long id;
    private Long userId;
    private String email;
    private String clientId;
    private String ip;
    private String userAgent;
    private boolean success;
    private String failureReason;
    private LocalDateTime createdAt;

    public static LoginHistoryResponse from(LoginHistory h) {
        return LoginHistoryResponse.builder()
                .id(h.getId())
                .userId(h.getUserId())
                .email(h.getEmail())
                .clientId(h.getClientId())
                .ip(h.getIp())
                .userAgent(h.getUserAgent())
                .success(h.isSuccess())
                .failureReason(h.getFailureReason())
                .createdAt(h.getCreatedAt())
                .build();
    }
}
