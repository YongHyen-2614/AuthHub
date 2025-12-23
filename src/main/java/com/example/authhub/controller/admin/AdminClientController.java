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

    /**
     * Client 생성
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Body: ClientCreateRequest(clientId, clientSecret, redirectUri, allowedScopes, accessTokenValidity, refreshTokenValidity, ...)
     *
     * [정책]
     * - clientId는 유일해야 한다(중복 시 예외 처리 필요)
     * - clientSecret은 저장 전 반드시 해시(PasswordEncoder 등) 처리하는 것을 권장한다.
     *
     * [응답]
     * - ApiResponse<ClientResponse>
     * - code/message: "CLIENT_CREATE_SUCCESS" (현재 컨트롤러 고정 문자열)
     *
     * [주의]
     * - 운영 환경에서는 clientSecret “평문 반환”을 제한하거나 1회성 노출 정책을 권장한다.
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> create(@Valid @RequestBody ClientCreateRequest req) {
        return ResponseEntity.ok(
                ApiResponse.success(
                        "CLIENT_CREATE_SUCCESS",
                        "Client 생성 성공",
                        adminClientService.create(req)
                )
        );
    }

    /**
     * Client 목록 조회 (페이징)
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Query: Pageable(page, size, sort)
     *
     * [응답]
     * - ApiResponse<Page<ClientResponse>>
     * - code/message: "CLIENT_LIST_SUCCESS"
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<ClientResponse>>> list(Pageable pageable) {
        return ResponseEntity.ok(
                ApiResponse.success(
                        "CLIENT_LIST_SUCCESS",
                        "Client 목록 조회 성공",
                        adminClientService.list(pageable)
                )
        );
    }

    /**
     * Client 단건 조회
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Path: /admin/clients/{clientId}
     *
     * [응답]
     * - ApiResponse<ClientResponse>
     * - code/message: "CLIENT_GET_SUCCESS"
     */
    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> get(@PathVariable String clientId) {
        return ResponseEntity.ok(
                ApiResponse.success(
                        "CLIENT_GET_SUCCESS",
                        "Client 조회 성공",
                        adminClientService.get(clientId)
                )
        );
    }

    /**
     * Client 수정
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Path: /admin/clients/{clientId}
     * - Body: ClientUpdateRequest(...)
     *
     * [정책]
     * - clientSecret 변경을 update에 포함할지 여부는 운영 정책에 따라 분리 권장(rotate-secret).
     *
     * [응답]
     * - ApiResponse<ClientResponse>
     * - code/message: "CLIENT_UPDATE_SUCCESS"
     */
    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<ClientResponse>> update(
            @PathVariable String clientId,
            @Valid @RequestBody ClientUpdateRequest req
    ) {
        return ResponseEntity.ok(
                ApiResponse.success(
                        "CLIENT_UPDATE_SUCCESS",
                        "Client 수정 성공",
                        adminClientService.update(clientId, req)
                )
        );
    }

    /**
     * Client 삭제
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Path: /admin/clients/{clientId}
     *
     * [정책]
     * - 삭제 시 해당 clientId로 발급된 세션/토큰(Refresh 등) 처리 정책이 필요할 수 있다.
     *
     * [응답]
     * - ApiResponse<Void>
     * - code/message: "CLIENT_DELETE_SUCCESS"
     */
    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable String clientId) {
        adminClientService.delete(clientId);
        return ResponseEntity.ok(
                ApiResponse.success(
                        "CLIENT_DELETE_SUCCESS",
                        "Client 삭제 성공"
                )
        );
    }
}
