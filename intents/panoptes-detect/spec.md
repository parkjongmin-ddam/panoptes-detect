# spec: 보호 대상 서비스 MVP (P0.5)

## 1. 개요
- 가상의 소규모 쇼핑 서비스. 회원·주문·파트너 API를 제공한다.
- 목적은 기능 자체보다 탐지 운영에 필요한 트래픽 유형과 로그를 만드는 것
- 보안 기본값을 지킨 정상 구현을 기준으로 한다.

## 2. 기술 스택
- Python 3.12, FastAPI, Uvicorn
- PostgreSQL 16, SQLAlchemy 2.x, Alembic
- 비밀번호 해시: argon2-cffi
- 테스트: pytest, httpx
- 컨테이너: python:3.12-slim 기반, amd64·arm64 공통 빌드

## 3. 기능
| 영역 | 엔드포인트 | 비고 |
|---|---|---|
| 상태 | `GET /health` | 인증 없음 |
| 회원 | `POST /auth/signup`, `POST /auth/login`, `POST /auth/logout` | 세션 쿠키(HttpOnly, SameSite=Lax) |
| 계정 보호 | 로그인 실패 누적 시 계정 일시 잠금 | 임계값·잠금 시간은 설정값 |
| 내 정보 | `GET /me` | 로그인 필요 |
| 주문 | `GET /orders`, `GET /orders/{id}`, `POST /orders` | 본인 주문만 조회 가능(소유자 검사) |
| 관리자 | `GET /admin/users` | role=admin만 허용 |
| 파트너 API | `GET /partner/products` | API 키 헤더 인증, 키는 DB에 해시로 저장 |
| 파일 | `POST /me/avatar` | 이미지 형식·크기 제한 |
| 화면 | 로그인·주문 목록 최소 HTML | WAF 오탐 분석용 폼 트래픽 확보 |

## 4. 로그 설계
- 형식: JSON 한 줄(stdout), Docker 로그로 수집 → Wazuh
- 공통 필드

| 필드 | 설명 |
|---|---|
| `ts` | ISO 8601 UTC |
| `request_id` | waf가 넘긴 `X-Request-ID`, 없으면 앱이 생성 |
| `client_ip` | `X-Forwarded-For`의 첫 값(waf만 신뢰) |
| `method`, `path`, `status`, `latency_ms` | 요청 메타 |
| `user_id` | 인증된 경우 |
| `event` | 아래 보안 이벤트 코드 |

- 보안 이벤트 코드

| event | 발생 조건 |
|---|---|
| `auth.login.success` | 로그인 성공 |
| `auth.login.failure` | 로그인 실패(사유: unknown_user / bad_password / locked) |
| `auth.lockout` | 계정 잠금 발생 |
| `authz.denied` | 권한 없는 리소스 접근(소유자 불일치, role 부족) |
| `apikey.invalid` | 잘못된 API 키 |
| `upload.rejected` | 파일 형식·크기 위반 |

- 비밀번호, 세션 값, API 키 원문은 로그에 남기지 않는다.

## 5. 설정
- 환경변수: `DATABASE_URL`, `SESSION_SECRET`, `LOCKOUT_THRESHOLD`, `LOCKOUT_MINUTES`, `TRUSTED_PROXY`
- 비밀값은 `.env`(git 제외), 예시는 `.env.example`

## 6. 테스트
- 기능: 회원가입·로그인·로그아웃, 주문 생성·조회, 관리자 접근
- 보안 동작: 타인 주문 조회 시 404/403 + `authz.denied` 로그, 잠금 임계값 도달 시 `auth.lockout`, 잘못된 API 키 시 `apikey.invalid`
- 로그: 모든 요청에 `request_id` 존재, 비밀값 미포함 확인

## 7. 저장소 구조(안)
```
panoptes-detect/
  compose.yaml            # profiles: core, siem
  .env.example
  .gitattributes          # 줄바꿈 LF 고정 (Windows·Mac 공용)
  waf/                    # nginx·ModSecurity 설정, 예외 룰
  app/                    # FastAPI 소스, Dockerfile, alembic
  tests/
  wazuh/rules/            # 커스텀 룰
  scripts/                # 트래픽·리포트 스크립트 (Python, OS 공용)
  docs/
  intents/panoptes-detect/
```

## 8. 범위 밖
- 결제, 이메일 발송, 외부 IdP 연동(필요 시 후속)
- 운영 수준 성능·가용성
