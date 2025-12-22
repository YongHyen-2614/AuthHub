package com.example.authhub.service.admin;

import com.example.authhub.domain.login.LoginHistory;
import com.example.authhub.dto.admin.response.LoginHistoryResponse;
import com.example.authhub.repository.LoginHistoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AdminLoginHistoryService {

    private final LoginHistoryRepository loginHistoryRepository;

    public Page<LoginHistoryResponse> search(
            String email,
            Long userId,
            String clientId,
            Boolean success,
            LocalDateTime from,
            LocalDateTime to,
            Pageable pageable
    ) {
        Specification<LoginHistory> spec = Specification.where(null);

        if (email != null && !email.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.like(root.get("email"), "%" + email + "%"));
        }
        if (userId != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("userId"), userId));
        }
        if (clientId != null && !clientId.isBlank()) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("clientId"), clientId));
        }
        if (success != null) {
            spec = spec.and((root, q, cb) -> cb.equal(root.get("success"), success));
        }
        if (from != null) {
            spec = spec.and((root, q, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), from));
        }
        if (to != null) {
            spec = spec.and((root, q, cb) -> cb.lessThanOrEqualTo(root.get("createdAt"), to));
        }

        return loginHistoryRepository.findAll(spec, pageable).map(LoginHistoryResponse::from);
    }
}
