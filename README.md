🔐 AuthHub

공통 인증 인프라(Auth Server)
여러 서비스에서 공통으로 사용할 수 있는 OAuth2 스타일로 확장 가능한 인증 서버

📌 1. 프로젝트 개요

AuthHub는 여러 서비스(Web, Mobile, Internal API 등)가 공통으로 사용할 수 있는 중앙 인증 서버를 목표로 한다.

현재는 JWT 기반 로그인/토큰 관리 기능을 구현했고, 이후 OAuth2 Authorization Code Flow로 확장하는 방향으로 설계했다.

🎯 2. 기간

2025.12.15 ~ 진행 중

12.18 ~ 서울 일정으로 잠시 중지

12.22 ~ 다시 시작

🎯 3. 핵심 목표

JWT 기반 인증

Access / Refresh Token 분리

Redis 기반 토큰/세션 관리

OAuth2 Authorization Code Flow 확장 가능 구조

공통 응답 포맷 & Global Exception Handling

Role 기반 권한 제어(Admin)

🏗 4. 전체 아키텍처

[ Client Apps ]
└── Web / Mobile / Other Services
  |
  v
[ AuthHub API Server ]
  |
  ├── 🗄 MySQL (영구 데이터)
  │  ├─ users
  │  ├─ clients
  │  └─ login_histories
  |
  └── ⚡ Redis (토큰/세션 관리)
    ├─ refresh:{refreshToken} → "{userId}:{clientId}"
    ├─ user_client:{userId}:{clientId} → "{refreshToken}"
    ├─ blacklist:access:{jti} → "true"
    ├─ logout_at:{userId} → epochMillis
    └─ logout_at:{userId}:{clientId} → epochMillis

🛠 5. 기술 스택

Java 17

Spring Boot 3.3

Spring Security

Spring Data JPA

Spring Data Redis

MySQL

Redis

JWT (jjwt)

✅ 6. 현재까지 구현된 기능 (Implemented)
🔐 6.1 인증 기능 (Auth)

회원가입

이메일 + 비밀번호 로그인

JWT Access Token 발급

Refresh Token 발급 및 회전(Rotation)

로그아웃(현재 기기)

로그아웃(전체 기기)

내 정보 조회(/auth/me)

🔄 6.2 토큰 관리 전략
1) Access Token

JWT 기반(Stateless)

로그아웃 시 Redis 블랙리스트(jti)를 사용해 만료 전 토큰을 예외적으로 무효화

2) Refresh Token

Redis 저장

(userId, clientId) 기준으로 세션 인덱스 저장

재발급 시 기존 Refresh Token 제거(회전/Rotation)

🧩 6.3 Client 기반 인증

clientId 기반 로그인

등록되지 않은 Client 요청 차단

Client별 토큰 만료 정책 지원

clients 테이블의 accessTokenValidity, refreshTokenValidity 활용

🧱 6.4 공통 응답 & 예외 처리

성공/실패 공통 응답 포맷(ApiResponse)

GlobalExceptionHandler 기반 예외 일괄 처리

ErrorCode / SuccessCode 기반 코드 체계화

(참고) 일부 Admin API는 구현에 따라 204 No Content 또는 200(ApiResponse)로 동작할 수 있어, 문서/구현을 한 방식으로 통일하는 것을 권장

🛡 6.5 보안

BCrypt 비밀번호 해시

JWT 서명 검증

Redis 기반 토큰 무효화(Blacklist/logoutAt)

Spring Security Filter(JwtAuthenticationFilter) 기반 인증 처리

Role 기반 접근 제어(ROLE_ADMIN)

🛠 6.6 관리자(Admin) 기능

Admin API는 아래 조건을 만족해야 접근 가능하다.

인증 필요

ROLE_ADMIN 필요 (@PreAuthorize("hasRole('ADMIN')"))

구현된 기능:

Client 등록 / 수정 / 삭제 / 조회(Page)

로그인 이력 조회(Page + 필터)

강제 로그아웃

전체 기기 강제 로그아웃

특정 clientId(기기) 강제 로그아웃

📬 7. API 명세 (현재 구현됨)

Auth API(/auth)

POST /auth/signup

POST /auth/login

POST /auth/refresh

POST /auth/logout (현재 기기 로그아웃)

POST /auth/logout-all (전체 기기 로그아웃)

GET /auth/me

Admin API(/admin)

POST /admin/clients

GET /admin/clients

GET /admin/clients/{clientId}

PUT /admin/clients/{clientId}

DELETE /admin/clients/{clientId}

GET /admin/login-histories

POST /admin/users/{userId}/force-logout

POST /admin/users/{userId}/clients/{clientId}/force-logout

노션 문서:
https://www.notion.so/API-2d1d46c5c16180509143eae38da09a07?source=copy_link

🗂 8. 데이터 설계 (현재 사용 중)
👤 Users

사용자 계정 정보

이메일 기반 로그인

역할(Role) 기반 권한 관리 (ROLE_USER, ROLE_ADMIN)

🧩 Clients

인증을 요청하는 외부 서비스 정보

Client별 토큰 정책 관리 (Access/Refresh TTL)

🧾 LoginHistories

로그인 성공/실패 이력 저장

email/userId/clientId/success/timestamp 기반 조회 지원(Admin)

⚡ 9. Redis 구조 (현재 사용 중)
🔄 Refresh Token

refresh:{refreshToken} → "{userId}:{clientId}" (TTL)

user_client:{userId}:{clientId} → "{refreshToken}" (TTL)

용도:

Refresh 검증

사용자 + clientId 기준 중복 로그인/세션 인덱싱

🚫 Access Token Blacklist

blacklist:access:{jti} → "true" (TTL)

용도:

로그아웃 시 현재 Access Token 즉시 무효화

⛔ 강제 로그아웃 logoutAt

전체 강제 로그아웃

logout_at:{userId} → epochMillis (TTL)

client별 강제 로그아웃

logout_at:{userId}:{clientId} → epochMillis (TTL)

용도:

JWT는 stateless라 원래 만료 전까지 유효하지만,
서버가 logoutAt을 저장해두고 토큰의 issuedAt(iat) ≤ logoutAt 이면 무효 처리하여 기존 Access Token을 강제로 차단한다.

🧭 10. 추후 구현 예정 기능 (Planned)
🌐 10.1 OAuth2 Authorization Code Flow

/oauth/authorize

/oauth/token

Authorization Code 발급 및 검증

Redirect URI 검증

State 파라미터를 통한 CSRF 방어

🤝 10.2 사용자 동의(Consent) 관리

user_consents 테이블

Client별 Scope 동의 기록

최초 로그인 시 동의 화면 제공

기존 동의 Scope 재사용

🌍 10.3 소셜 로그인 연동

Kakao / Naver

provider / provider_id 기반 계정 통합

LOCAL + 소셜 계정 공존 구조

🔐 10.4 보안 강화

Rate Limiting (Redis)

로그인 실패 횟수 제한

의심 로그인 탐지

🧠 11. 설계 철학 요약

OAuth2/OIDC 구조를 최대한 존중

실무에서 사용 가능한 인증 서버 구조 지향

Stateless JWT를 기본으로 하되, 예외적으로 Redis를 이용해 “무효화해야 하는 토큰/세션 정보만” 기록

확장 가능한 설계, 단계적 구현

🎯 12. 트러블 슈팅
문제 상황

중복 로그인 방지를 위해 로직을 넣었는데도 중복 로그인이 계속 발생

원인

Refresh Token은 지우더라도 기존 Access Token은 만료 전까지 계속 유효(Stateless)하다.
따라서 “기존 세션을 완전히 무효화”하려면 Access Token에 대한 추가 제어가 필요했다.

해결 방안 후보

A안: 이전 세션 자동 로그아웃(기존 토큰도 무효화)

B안: 로그인 자체를 거부(중복 로그인 차단)

현재 적용된 정책(정리)

기본 정책: B안(중복 로그인 거부)

(userId, clientId) 기준으로 이미 세션이 있으면 로그인 요청을 거부

예외/운영 기능: A안(강제 무효화 지원)

로그아웃/강제 로그아웃 시

블랙리스트(jti)로 현재 Access Token 즉시 무효화

logoutAt 저장 후, 토큰의 iat과 비교해 기존 Access Token을 서버에서 무효 처리

즉, “기본은 거부(B)”로 단순하게 유지하면서, 운영/보안 요구사항을 위해 “무효화(A)”를 함께 지원하는 구조다.

<img width="1272" height="750" alt="스크린샷 2025-12-16 134822" src="https://github.com/user-attachments/assets/ef9172b1-5fcf-4c0a-a3c1-cc87e89202cf" />
