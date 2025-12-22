package com.example.authhub.dto.admin.response;

import com.example.authhub.domain.client.Client;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class ClientResponse {
    private String clientId;
    private String name;
    private String redirectUri;
    private Long accessTokenValidity;
    private Long refreshTokenValidity;
    private String allowedScopes;

    public static ClientResponse from(Client c) {
        Long access = (c.getAccessTokenValidity() == null) ? null : c.getAccessTokenValidity().longValue();
        Long refresh = (c.getRefreshTokenValidity() == null) ? null : c.getRefreshTokenValidity().longValue();

        return ClientResponse.builder()
                .clientId(c.getClientId())
                .name(c.getName())
                .redirectUri(c.getRedirectUri())
                .accessTokenValidity(access)
                .refreshTokenValidity(refresh)
                .allowedScopes(c.getAllowedScopes())
                .build();
    }
}
