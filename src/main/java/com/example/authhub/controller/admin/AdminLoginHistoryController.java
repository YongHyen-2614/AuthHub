package com.example.authhub.controller.admin;

import com.example.authhub.dto.admin.response.LoginHistoryResponse;
import com.example.authhub.dto.auth.response.ApiResponse;
import com.example.authhub.service.admin.AdminLoginHistoryService;
import com.example.authhub.success.SuccessCode;
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
     * [권한] ADMIN 필요 (hasRole('ADMIN'))
     * [요청] Query: email, userId, clientId, success, from, to + Pageable
     * [응답] ApiResponse<Page<LoginHistoryResponse>>
     * - SuccessCode: ADMIN_LOGIN_HISTORY_LIST_SUCCESS
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
                        SuccessCode.ADMIN_LOGIN_HISTORY_LIST_SUCCESS.getCode(),
                        SuccessCode.ADMIN_LOGIN_HISTORY_LIST_SUCCESS.getMessage(),
                        result
                )
        );
    }
}
