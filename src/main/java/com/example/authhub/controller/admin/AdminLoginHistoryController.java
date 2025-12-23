package com.example.authhub.controller.admin;

import com.example.authhub.dto.admin.response.LoginHistoryResponse;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.service.admin.AdminLoginHistoryService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequiredArgsConstructor
@RequestMapping("/admin/login-histories")
public class AdminLoginHistoryController {

    private final AdminLoginHistoryService adminLoginHistoryService;

    /**
     * 로그인 이력 조회 (검색 + 페이징)
     *
     * [권한]
     * - ADMIN 필요 (hasRole('ADMIN'))
     *
     * [요청]
     * - Query(선택):
     *   - email: 사용자 이메일
     *   - userId: 사용자 PK
     *   - clientId: 클라이언트 ID
     *   - success: 성공 여부(true/false)
     *   - from/to: 기간 필터 (ISO_DATE_TIME)
     * - Pageable(page, size, sort)
     *
     * [응답]
     * - ApiResponse<Page<LoginHistoryResponse>>
     * - code/message: "LOGIN_HISTORY_LIST_SUCCESS"
     *
     * [주의]
     * - from/to가 없으면 전체 기간을 조회하므로 데이터가 많아질 수 있다(반드시 페이징 사용 권장).
     */
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<ApiResponse<Page<LoginHistoryResponse>>> list(
            @RequestParam(required = false) String email,
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) String clientId,
            @RequestParam(required = false) Boolean success,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            Pageable pageable
    ) {
        Page<LoginHistoryResponse> result =
                adminLoginHistoryService.search(email, userId, clientId, success, from, to, pageable);

        return ResponseEntity.ok(
                ApiResponse.success(
                        "LOGIN_HISTORY_LIST_SUCCESS",
                        "로그인 이력 조회 성공",
                        result
                )
        );
    }
}
