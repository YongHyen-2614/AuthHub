package com.example.authhub.domain.user;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "user")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * 로그인 ID (LOCAL 로그인용)
     * OAuth 유저는 null 가능
     */
    @Column(unique = true)
    private String username;

    /**
     * 비밀번호 (LOCAL 로그인용)
     * OAuth 유저는 null 가능
     */
    private String password;

    /**
     * 이메일 (OAuth / LOCAL 공통 식별자)
     */
    @Column(nullable = false, unique = true)
    private String email;

    /**
     * OAuth 제공자
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;

    /**
     * OAuth 제공자에서 내려주는 사용자 ID
     * LOCAL 로그인은 null
     */
    private String providerId;

    /**
     * 사용자 권한
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;

    /**
     * 계정 활성 여부
     */
    @Column(nullable = false)
    private boolean enabled;

    /**
     * 생성 시각
     */
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    /**
     * 수정 시각
     */
    private LocalDateTime updatedAt;

    /* =========================
       JPA 생명주기 콜백
       ========================= */

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.enabled = true;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    /* =========================
       비즈니스 메서드
       ========================= */

    public void changePassword(String encodedPassword) {
        this.password = encodedPassword;
    }

    public void deactivate() {
        this.enabled = false;
    }
}
