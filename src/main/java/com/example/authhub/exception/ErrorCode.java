package com.example.authhub.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {

    /* Common */
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "C001", "잘못된 요청입니다."),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "C002", "서버 오류가 발생했습니다."),

    /* Auth */
    EMAIL_ALREADY_EXISTS(HttpStatus.BAD_REQUEST, "A001", "이미 존재하는 이메일입니다."),
    INVALID_CREDENTIALS(HttpStatus.BAD_REQUEST, "A002", "이메일 또는 비밀번호가 올바르지 않습니다."),
    UNAUTHORIZED(HttpStatus.UNAUTHORIZED, "A003", "인증이 필요합니다."),
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "A004", "Refresh Token이 유효하지 않습니다."),
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "A005", "사용자를 찾을 수 없습니다."),
    INVALID_CLIENT(HttpStatus.BAD_REQUEST, "A006", "유효하지 않은 clientId 입니다."),
    INVALID_AUTHORIZATION_HEADER(HttpStatus.UNAUTHORIZED, "A007", "Authorization 헤더가 유효하지 않습니다."),
    ALREADY_LOGGED_IN(HttpStatus.BAD_REQUEST, "A008", "이미 로그인 되었습니다."),

    /* Admin */
    FORBIDDEN(HttpStatus.FORBIDDEN, "A009", "권한이 없습니다."),
    CLIENT_ALREADY_EXISTS(HttpStatus.BAD_REQUEST, "A010", "이미 존재하는 clientId 입니다."),
    CLIENT_NOT_FOUND(HttpStatus.NOT_FOUND, "A011", "Client를 찾을 수 없습니다."),
    INVALID_VALIDITY_SECONDS(HttpStatus.BAD_REQUEST, "A012", "토큰 만료 시간 값이 올바르지 않습니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;

    ErrorCode(HttpStatus status, String code, String message) {
        this.status = status;
        this.code = code;
        this.message = message;
    }
}
