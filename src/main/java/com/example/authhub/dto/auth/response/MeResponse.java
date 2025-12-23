package com.example.authhub.dto.auth.response;

import lombok.Builder;
import lombok.Getter;

import java.util.List;

@Getter
@Builder
public class MeResponse {

    private Long userId;
    private String email;
    private String clientId;
    private List<String> roles;
}
