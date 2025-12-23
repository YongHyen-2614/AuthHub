package com.example.authhub.controller.admin;

import com.example.authhub.dto.admin.request.ClientCreateRequest;
import com.example.authhub.dto.admin.request.ClientUpdateRequest;
import com.example.authhub.dto.admin.response.ClientResponse;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.service.admin.AdminClientService;
import com.example.authhub.success.SuccessCode;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin/clients")
public class AdminClientController {

    private final AdminClientService adminClientService;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> create(
            @Valid @RequestBody ClientCreateRequest req
    ) {
        ClientResponse created = adminClientService.create(req);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.CLIENT_CREATE_SUCCESS.getCode(),
                        SuccessCode.CLIENT_CREATE_SUCCESS.getMessage(),
                        created
                )
        );
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<ClientResponse>>> list(Pageable pageable) {
        Page<ClientResponse> result = adminClientService.list(pageable);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.CLIENT_LIST_SUCCESS.getCode(),
                        SuccessCode.CLIENT_LIST_SUCCESS.getMessage(),
                        result
                )
        );
    }

    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> get(@PathVariable String clientId) {
        ClientResponse result = adminClientService.get(clientId);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.CLIENT_GET_SUCCESS.getCode(),
                        SuccessCode.CLIENT_GET_SUCCESS.getMessage(),
                        result
                )
        );
    }

    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> update(
            @PathVariable String clientId,
            @Valid @RequestBody ClientUpdateRequest req
    ) {
        ClientResponse updated = adminClientService.update(clientId, req);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.CLIENT_UPDATE_SUCCESS.getCode(),
                        SuccessCode.CLIENT_UPDATE_SUCCESS.getMessage(),
                        updated
                )
        );
    }

    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String clientId) {
        adminClientService.delete(clientId);

        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.CLIENT_DELETE_SUCCESS.getCode(),
                        SuccessCode.CLIENT_DELETE_SUCCESS.getMessage()
                )
        );
    }
}
