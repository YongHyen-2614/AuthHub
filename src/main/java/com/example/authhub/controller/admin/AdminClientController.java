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

    /**
     * Client 생성
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Body: ClientCreateRequest
     * [응답] ApiResponse<ClientResponse>
     * - SuccessCode: ADMIN_CLIENT_CREATE_SUCCESS
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> create(@Valid @RequestBody ClientCreateRequest req) {
        ClientResponse data = adminClientService.create(req);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_CLIENT_CREATE_SUCCESS.getCode(),
                        SuccessCode.ADMIN_CLIENT_CREATE_SUCCESS.getMessage(),
                        data
                )
        );
    }

    /**
     * Client 목록 조회(페이징)
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Pageable
     * [응답] ApiResponse<Page<ClientResponse>>
     * - SuccessCode: ADMIN_CLIENT_LIST_SUCCESS
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<ClientResponse>>> list(Pageable pageable) {
        Page<ClientResponse> data = adminClientService.list(pageable);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_CLIENT_LIST_SUCCESS.getCode(),
                        SuccessCode.ADMIN_CLIENT_LIST_SUCCESS.getMessage(),
                        data
                )
        );
    }

    /**
     * Client 단건 조회
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Path: clientId
     * [응답] ApiResponse<ClientResponse>
     * - SuccessCode: ADMIN_CLIENT_GET_SUCCESS
     */
    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> get(@PathVariable String clientId) {
        ClientResponse data = adminClientService.get(clientId);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_CLIENT_GET_SUCCESS.getCode(),
                        SuccessCode.ADMIN_CLIENT_GET_SUCCESS.getMessage(),
                        data
                )
        );
    }

    /**
     * Client 수정
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Path: clientId, Body: ClientUpdateRequest
     * [응답] ApiResponse<ClientResponse>
     * - SuccessCode: ADMIN_CLIENT_UPDATE_SUCCESS
     */
    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> update(
            @PathVariable String clientId,
            @Valid @RequestBody ClientUpdateRequest req
    ) {
        ClientResponse data = adminClientService.update(clientId, req);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_CLIENT_UPDATE_SUCCESS.getCode(),
                        SuccessCode.ADMIN_CLIENT_UPDATE_SUCCESS.getMessage(),
                        data
                )
        );
    }

    /**
     * Client 삭제
     *
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Path: clientId
     * [응답] ApiResponse<Void>
     * - SuccessCode: ADMIN_CLIENT_DELETE_SUCCESS
     */
    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String clientId) {
        adminClientService.delete(clientId);
        return ResponseEntity.ok(
                ApiResponse.success(
                        SuccessCode.ADMIN_CLIENT_DELETE_SUCCESS.getCode(),
                        SuccessCode.ADMIN_CLIENT_DELETE_SUCCESS.getMessage()
                )
        );
    }
}
