🔐 AuthHub
--------------------
공통 인증 인프라 (Auth Server)
여러 서비스에서 공통으로 사용할 수 있는 OAuth2 스타일 인증 서버

📌 1. 프로젝트 개요
--------------------
AuthHub는 여러 서비스(Web, Mobile, Internal API 등)가
공통으로 사용할 수 있는 중앙 인증 서버를 목표로 한다.

기존에 학습했던 인증·보안 관련 기술을 복습하고,
이를 기반으로 실무에서 사용 가능한 구조로 확장하는 데 초점을 맞췄다.

🎯기간
-------
2025.12.15 ~ 진행중

🎯 핵심 목표
--------------------
🔑 JWT 기반 인증

🔄 Access / Refresh Token 분리

⚡ Redis 기반 토큰 관리

🌐 OAuth2 Authorization Code Flow 확장 가능 구조

🧩 공통 응답 포맷 & Global Exception Handling

🏗 2. 전체 아키텍처
--------------------
[ Client Apps ]
   └── Web / Mobile / Other Services
        |
        v
[ AuthHub API Server ]
        |
        ├── 🗄 MySQL (영구 데이터)
        │     ├─ users
        │     ├─ clients
        │     └─ login_histories
        |
        └── ⚡ Redis (토큰 관리)
              ├─ refresh_token:{token}
              └─ blacklist:access:{jti}

🛠 3. 기술 스택
--------------------
☕ Java 17

🌱 Spring Boot 3.3

🔐 Spring Security

🧬 Spring Data JPA

🚀 Spring Data Redis

🗄 MySQL

⚡ Redis

🔑 JWT (jjwt)

✅ 4. 현재까지 구현된 기능 (Implemented)
-----------------------------------------
🔐 4.1 인증 기능
--------------------
👤 회원가입

📧 이메일 + 비밀번호 로그인

🔑 JWT Access Token 발급

🔄 Refresh Token 발급 및 회전(Rotation)

🚪 로그아웃

Access Token 블랙리스트 처리

Refresh Token 삭제

🔄 4.2 토큰 관리 전략
-----------------------
🔑 Access Token

JWT 기반 (Stateless)

로그아웃 시 Redis 블랙리스트(jti) 활용

🔄 Refresh Token

Redis 저장

Client별 TTL 적용

재발급 시 기존 토큰 무효화 (Rotation)

🧩 4.3 Client 기반 인증
------------------------
clientId 기반 로그인

등록되지 않은 Client 요청 차단

Client별 토큰 만료 정책 지원

🧱 4.4 공통 응답 & 예외 처리
----------------------------
성공 / 실패 공통 응답 포맷

GlobalExceptionHandler를 통한 예외 일괄 처리

에러 코드 체계화 (ErrorCode, SuccessCode)

🛡 4.5 보안
------------
🔒 BCrypt 비밀번호 해시

✍️ JWT 서명 검증

🚫 Redis 기반 토큰 무효화

🧩 Spring Security Filter 기반 인증 처리

📬 5. API 명세 (현재 구현됨)
----------------------------
👤 5.1 회원가입
---------------
POST /auth/signup

{
  "email": "user@test.com",
  "password": "password123"
}

🔐 5.2 로그인
--------------
POST /auth/login

{
  "email": "user@test.com",
  "password": "password123",
  "clientId": "web-client"
}

🔄 5.3 토큰 재발급
-------------------

POST /auth/refresh

{
  "refreshToken": "uuid-refresh-token",
  "clientId": "web-client"
}

🚪 5.4 로그아웃
----------------

POST /auth/logout

Header

Authorization: Bearer {accessToken}

🗂 6. 데이터 설계 (현재 사용 중)
-------------------------------
👤 Users

사용자 계정 정보

이메일 기반 로그인

역할(Role) 기반 권한 관리

🧩 Clients

인증을 요청하는 외부 서비스 정보

Client별 토큰 정책 관리

⚡ 7. Redis 구조 (현재 사용 중)
--------------------------------
🔄 Refresh Token
refresh_token:{token} → userId, clientId

🚫 Access Token Blacklist
blacklist:access:{jti} → true

🧭 8. 추후 구현 예정 기능 (Planned)
------------------------------------

아래 기능들은 현재 설계에 반영되어 있으며, 단계적으로 확장할 예정이다.

🌐 8.1 OAuth2 Authorization Code Flow
--------------------------------------

/oauth/authorize

/oauth/token

Authorization Code 발급 및 검증

Redirect URI 검증

State 파라미터를 통한 CSRF 방어

🤝 8.2 사용자 동의(Consent) 관리
---------------------------------
user_consents 테이블

Client별 Scope 동의 기록

최초 로그인 시 동의 화면 제공

기존 동의 Scope 재사용

🙋 8.3 내 정보 조회 API
------------------------
/auth/me

Access Token 기반 사용자 정보 조회
AuthHub를 User Info 서버로 활용

🌍 8.4 소셜 로그인 연동
-----------------------
Kakao / Naver

provider / provider_id 기반 계정 통합

LOCAL + 소셜 계정 공존 구조

🛠 8.5 관리자(Admin) 기능
-------------------------
Client 등록 / 수정 / 삭제

로그인 이력 조회

관리자 권한(Role 기반) 접근 제어

🔐 8.6 보안 강화
----------------
Rate Limiting (Redis)

로그인 실패 횟수 제한

의심 로그인 탐지

🧠 9. 설계 철학 요약
--------------------
📘 OAuth2/OIDC 구조를 최대한 존중

🏗 실무에서 사용 가능한 인증 서버 구조

🔄 Stateless JWT + Redi📘 OAuth2/OIDC 구조를 최대한 존중

🚀 확장 가능한 설계, 단계적 구현

🎯10. 트러블 슈팅
---------------

문제 상황: 중복 로그인 방지를 위해 코드를 짜던 중 로직이 있음에도 불구하고 중복 로그인이 계속 됨

원인: Refresh Token은 지우고 있는데, 기존 Access Token은 그대로 살아 있음

해결 방안: 

A 안 ‘이전 세션 자동 로그아웃 처리’
B 안 ‘로그인 자체를 거부’

채택: JWT는 기본적으로 stateless, 서버가 토큰을 기억하지 않고, 만료 전까지 유효. 그렇기에 중복 로그인이 발생. 
이런 상황에서 B안을 선택 시 서버가 로그인 상태를 항상 기억하고 있어야 함. 
그렇게 되면 세션 서버를 만드는 것과 다를게 없어 JWT 서버의 의미가 없음 그렇기에 Redis를 사용해 예외적인 경우에만 Redis로 사용하면 안 되는 것을 기록. 
A안 채택

결과:

<img width="1272" height="750" alt="스크린샷 2025-12-16 134822" src="https://github.com/user-attachments/assets/ef9172b1-5fcf-4c0a-a3c1-cc87e89202cf" />


자동 로그아웃 가능, 이후에 중복 로그인 시 오류 메세지가 나오도록 설정 후 동작

