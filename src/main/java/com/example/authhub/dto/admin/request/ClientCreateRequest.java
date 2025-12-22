package com.example.authhub.dto.admin.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class ClientCreateRequest {
    @NotBlank
    private String clientId;

    @NotBlank
    private String clientSecret;

    @NotBlank
    private String name;

    private String redirectUri; // OAuth 대비

    private Long accessTokenValidity;   // seconds
    private Long refreshTokenValidity;  // seconds

    private String allowedScopes;
}
