# P0.5 보호 대상 서비스(panoptes-shop) 구성 기록

- 일자: 2026-10-27
- 환경: Mac mini M4 (arm64), OrbStack
- 결과: 완료 — WAF 뒤에 신규 앱 배치, 보안 이벤트 구조화 로그 동작 확인

## 1. 목적

탐지 운영 실습에 쓸 트래픽과 로그를 만들기 위해, 보안 기본값을 지킨 정상 웹·API 서비스를 직접 개발. 기능 자체보다 로그 설계가 핵심.

## 2. 구성 요소

| 항목 | 값 |
|---|---|
| 프레임워크 | FastAPI 0.115 + Uvicorn |
| DB | PostgreSQL 16 |
| 비밀번호 해시 | argon2 |
| 세션 | 서버측 세션 테이블 + HttpOnly·SameSite=Lax 쿠키 |
| 컨테이너 | python:3.12-slim (amd64·arm64 공통), 비특권 사용자 실행 |

## 3. 기능과 보안 이벤트

| 영역 | 엔드포인트 | 보안 이벤트 |
|---|---|---|
| 회원 | signup / login / logout | auth.login.success, auth.login.failure, auth.lockout |
| 계정 보호 | 로그인 실패 누적 시 잠금(기본 5회/10분) | auth.lockout |
| 주문 | 본인 주문만 조회(소유자 검사) | authz.denied (reason=owner) |
| 관리자 | role=admin만 허용 | authz.denied (reason=role) |
| 파트너 API | X-API-Key 헤더 인증(DB에 SHA-256 저장) | apikey.invalid |
| 파일 업로드 | 형식·크기 제한 | upload.rejected |

- 소유자 불일치 조회는 존재를 숨기려 404로 응답하되 authz.denied 이벤트는 기록
- 비밀번호·세션·API 키 원문은 로그에 남기지 않음

## 4. 로그 설계

- 형식: 요청마다 JSON 한 줄(stdout)
- 공통 필드: ts, request_id, client_ip, method, path, status, latency_ms, user_id(인증 시), event(보안 이벤트)
- request_id: WAF가 넘긴 X-Request-ID를 이어받고, 없으면 앱이 생성 → WAF 로그와 앱 로그를 같은 ID로 연결
- client_ip: X-Forwarded-For 첫 값(WAF 뒤에 있을 때만 신뢰)

## 5. 아키텍처 (P0.5)

```
client → waf (nginx + ModSecurity + CRS) → app (FastAPI) → db (PostgreSQL)
   edge           edge·dmz                   dmz·internal      internal
```

- 네트워크 분리: waf만 외부 포트 공개. app·db는 내부 네트워크 전용(db는 internal만)
- echo 백엔드는 echo profile로 분리(P0 회귀용, 기본 비활성)

## 6. 검증

- pytest 10건 통과: 기능(회원·주문·관리자), 보안 동작(소유자 검사·계정 잠금·API 키·업로드 거부), 로그 위생(request_id 존재·비밀값 미포함·XFF 반영)
- WAF 경유 실호출 확인
  - GET /health → 200
  - 로그인 실패 → 401, `auth.login.failure`(reason=bad_password)
  - 로그인 성공 → 200, `auth.login.success`(user_id 포함)

## 7. 발견: client_ip가 게이트웨이로 치환됨

- WAF 경유 요청의 client_ip가 실제 클라이언트가 아니라 OrbStack 게이트웨이(192.168.107.1)로 기록됨
- 원인: 앱의 X-Forwarded-For 처리는 정상이나, WAF가 받는 시점에 이미 OrbStack 포트포워딩이 원 IP를 게이트웨이로 바꿈
- 영향: IP 기반 탐지(같은 IP 반복 등)는 원 IP 보존이 필요 → P3 착수 전 OrbStack/WAF 레이어에서 해결
- 현재 범위: 앱 구현은 완성. spec의 "client_ip = X-Forwarded-For 첫 값" 설계는 유효

## 8. 구현 판단 메모

- 스키마: MVP는 startup create_all(Alembic은 스키마 변경 발생 시 도입)
- 세션: 서버측 저장(세션 이벤트 로깅 용이)
- 로그 전달: request.state 사용 — Starlette BaseHTTPMiddleware는 엔드포인트의 ContextVar가 미들웨어로 전파되지 않음(테스트로 확인)
- 타임존: SQLite(테스트)는 naive 반환 → as_aware()로 보정, Postgres는 aware

## 9. 블로그 포인트 (초안용)

- "탐지를 전제로 앱을 설계한다": 보안 이벤트 코드를 먼저 정하고 그에 맞춰 로그를 남긴 점
- WAF(요청 단위)와 앱(비즈니스 로직 단위) 로그를 request_id로 잇는 구조
- 컨테이너 네트워크 분리(db를 internal 전용으로)
- OrbStack 포트포워딩의 IP 치환 — 로컬 랩에서 흔히 놓치는 지점

## 10. 다음 단계

- 앱 로그를 Wazuh로 수집(현재 WAF 감사 로그만 수집 중)
- 앱 보안 이벤트 대상 탐지 룰 작성(P3: 로그인 실패 급증, 소유자 위반 등)
