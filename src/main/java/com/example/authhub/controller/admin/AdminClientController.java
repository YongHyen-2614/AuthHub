package com.example.authhub.controller.admin;

import com.example.authhub.dto.admin.request.ClientCreateRequest;
import com.example.authhub.dto.admin.request.ClientUpdateRequest;
import com.example.authhub.dto.admin.response.ClientResponse;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.service.admin.AdminClientService;
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
    public ResponseEntity<ApiResponse<ClientResponse>> create(@Valid @RequestBody ClientCreateRequest req) {
        return ResponseEntity.ok(ApiResponse.success("CLIENT_CREATE_SUCCESS", "Client 생성 성공",
                adminClientService.create(req)));
    }

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<ClientResponse>>> list(Pageable pageable) {
        return ResponseEntity.ok(ApiResponse.success("CLIENT_LIST_SUCCESS", "Client 목록 조회 성공",
                adminClientService.list(pageable)));
    }

    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> get(@PathVariable String clientId) {
        return ResponseEntity.ok(ApiResponse.success("CLIENT_GET_SUCCESS", "Client 조회 성공",
                adminClientService.get(clientId)));
    }

    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> update(
            @PathVariable String clientId,
            @Valid @RequestBody ClientUpdateRequest req
    ) {
        return ResponseEntity.ok(ApiResponse.success("CLIENT_UPDATE_SUCCESS", "Client 수정 성공",
                adminClientService.update(clientId, req)));
    }

    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String clientId) {
        adminClientService.delete(clientId);
        return ResponseEntity.ok(ApiResponse.success("CLIENT_DELETE_SUCCESS", "Client 삭제 성공"));
    }
}
