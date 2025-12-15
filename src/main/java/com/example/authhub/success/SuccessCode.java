package com.example.authhub.success;

import lombok.Getter;

@Getter
public enum SuccessCode {

    SIGNUP_SUCCESS("S001", "회원가입이 완료되었습니다."),
    LOGIN_SUCCESS("S002", "로그인에 성공했습니다."),
    LOGOUT_SUCCESS("S003", "로그아웃 되었습니다."),
    TOKEN_REFRESH_SUCCESS("S004", "Access Token이 재발급되었습니다.");

    private final String code;
    private final String message;

    SuccessCode(String code, String message) {
        this.code = code;
        this.message = message;
    }
}
