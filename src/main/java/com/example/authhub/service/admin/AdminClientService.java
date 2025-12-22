package com.example.authhub.service.admin;

import com.example.authhub.domain.client.Client;
import com.example.authhub.dto.admin.request.ClientCreateRequest;
import com.example.authhub.dto.admin.request.ClientUpdateRequest;
import com.example.authhub.dto.admin.response.ClientResponse;
import com.example.authhub.exception.AuthException;
import com.example.authhub.exception.ErrorCode;
import com.example.authhub.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class AdminClientService {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientResponse create(ClientCreateRequest req) {
        if (clientRepository.findByClientId(req.getClientId()).isPresent()) {
            throw new AuthException(ErrorCode.INVALID_CLIENT);
        }

        Client client = Client.builder()
                .clientId(req.getClientId())
                .clientSecret(passwordEncoder.encode(req.getClientSecret()))
                .name(req.getName())
                .redirectUri(req.getRedirectUri())
                .accessTokenValidity(req.getAccessTokenValidity())
                .refreshTokenValidity(req.getRefreshTokenValidity())
                .allowedScopes(req.getAllowedScopes())
                .build();

        return ClientResponse.from(clientRepository.save(client));
    }

    @Transactional(readOnly = true)
    public Page<ClientResponse> list(Pageable pageable) {
        return clientRepository.findAll(pageable).map(ClientResponse::from);
    }

    @Transactional(readOnly = true)
    public ClientResponse get(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CLIENT));
        return ClientResponse.from(client);
    }

    public ClientResponse update(String clientId, ClientUpdateRequest req) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CLIENT));

        if (req.getClientSecret() != null && !req.getClientSecret().isBlank()) {
            client.setClientSecret(passwordEncoder.encode(req.getClientSecret()));
        }
        if (req.getName() != null) client.setName(req.getName());
        if (req.getRedirectUri() != null) client.setRedirectUri(req.getRedirectUri());
        if (req.getAccessTokenValidity() != null) client.setAccessTokenValidity(req.getAccessTokenValidity());
        if (req.getRefreshTokenValidity() != null) client.setRefreshTokenValidity(req.getRefreshTokenValidity());
        if (req.getAllowedScopes() != null) client.setAllowedScopes(req.getAllowedScopes());

        return ClientResponse.from(client);
    }

    public void delete(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CLIENT));
        clientRepository.delete(client);
    }
}
