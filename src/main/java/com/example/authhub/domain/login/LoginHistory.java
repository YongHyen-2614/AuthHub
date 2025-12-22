package com.example.authhub.domain.login;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class LoginHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Long userId;            // 실패면 null 가능
    private String email;           // 시도한 이메일
    private String clientId;        // 시도한 clientId
    private String ip;
    private String userAgent;

    private boolean success;
    private String failureReason;   // 성공이면 null

    private LocalDateTime createdAt;

    @PrePersist
    void prePersist() {
        this.createdAt = LocalDateTime.now();
    }

    public static LoginHistory success(Long userId, String email, String clientId, String ip, String ua) {
        LoginHistory h = new LoginHistory();
        h.userId = userId;
        h.email = email;
        h.clientId = clientId;
        h.ip = ip;
        h.userAgent = ua;
        h.success = true;
        return h;
    }

    public static LoginHistory fail(String email, String clientId, String ip, String ua, String reason) {
        LoginHistory h = new LoginHistory();
        h.email = email;
        h.clientId = clientId;
        h.ip = ip;
        h.userAgent = ua;
        h.success = false;
        h.failureReason = reason;
        return h;
    }
}
