package com.example.authhub.dto.admin.request;

import lombok.Getter;

@Getter
public class ClientUpdateRequest {
    private String clientSecret;
    private String name;
    private String redirectUri;

    private Long accessTokenValidity;
    private Long refreshTokenValidity;

    private String allowedScopes;
}
