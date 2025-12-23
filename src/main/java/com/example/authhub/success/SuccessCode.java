package com.example.authhub.success;

import lombok.Getter;

@Getter
public enum SuccessCode {

    SIGNUP_SUCCESS("S001", "회원가입이 완료되었습니다."),
    LOGIN_SUCCESS("S002", "로그인에 성공했습니다."),
    LOGOUT_SUCCESS("S003", "로그아웃 되었습니다."),
    TOKEN_REFRESH_SUCCESS("S004", "Access Token이 재발급되었습니다."),

    /* Admin */
    CLIENT_CREATE_SUCCESS("S005", "Client 생성에 성공했습니다."),
    CLIENT_LIST_SUCCESS("S006", "Client 목록 조회에 성공했습니다."),
    CLIENT_GET_SUCCESS("S007", "Client 조회에 성공했습니다."),
    CLIENT_UPDATE_SUCCESS("S008", "Client 수정에 성공했습니다."),
    CLIENT_DELETE_SUCCESS("S009", "Client 삭제에 성공했습니다."),
    LOGIN_HISTORY_LIST_SUCCESS("S010", "로그인 이력 조회에 성공했습니다."),
    FORCE_LOGOUT_SUCCESS("S011", "강제 로그아웃에 성공했습니다.");

    private final String code;
    private final String message;

    SuccessCode(String code, String message) {
        this.code = code;
        this.message = message;
    }
}
