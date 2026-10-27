# panoptes-detect

웹 서비스 앞단의 WAF와 SIEM으로 탐지 운영(Detection Operations) 흐름을 직접 구성하는 검증 프로젝트입니다.
보호 대상 서비스부터 직접 개발하고, WAF 탐지 → 로그 수집 → 탐지 룰 → 오탐 튜닝 → 가상 패치·차단 전환까지 단계별로 실측하며 진행합니다.

이름은 그리스 신화에서 모든 것을 보는 감시자 아르고스의 별칭 Panoptes에서 가져왔습니다.

## 목표

- 탐지를 전제로 로그를 설계한 보호 대상 서비스 구성
- WAF(ModSecurity + OWASP CRS) 이벤트와 애플리케이션 보안 이벤트를 SIEM(Wazuh)으로 수집
- 단일 요청 탐지(WAF)와 여러 요청을 묶는 상관분석(SIEM) 룰 작성
- 정상 트래픽 기준 오탐 튜닝 후 차단 모드 전환, 취약 엔드포인트 가상 패치
- 모든 판단은 원본 로그 기준 실측으로 검증하고 기록

## 아키텍처

```
client
  │  HTTP (Host: shop.panoptes.lab)
  ▼
waf ── nginx + ModSecurity v3 + OWASP CRS 4.30.0      network: edge, dmz
  │      └ logs/modsec/audit.log (JSON)
  ▼
app ── panoptes-shop (FastAPI)                        network: dmz, internal
  │      └ logs/app/app.log (JSON, 보안 이벤트 코드)
  ▼
db  ── PostgreSQL 16                                   network: internal

Wazuh agent (Mac) ── 두 로그 수집 ──▶ Wazuh manager ─ 룰 평가 ─▶ indexer / dashboard
```

- 외부 포트는 WAF만 공개합니다. DB는 내부 네트워크 전용입니다.
- WAF가 넘긴 `X-Request-ID`를 앱이 그대로 사용해 WAF 로그와 앱 로그를 같은 ID로 연결합니다.
- 수집 경로는 agent 로컬 설정이 아니라 Wazuh 그룹 설정(`agent.conf`)으로 배포합니다.

## 구성 요소

| 구성 요소 | 버전 / 값 |
| --- | --- |
| WAF | owasp/modsecurity-crs (nginx, 다이제스트 고정), ModSecurity v3.0.17, CRS 4.30.0, Paranoia Level 1 |
| 앱 | Python 3.12, FastAPI, SQLAlchemy 2.x, argon2 |
| DB | PostgreSQL 16 |
| SIEM | Wazuh 4.14.9 single-node (manager, indexer, dashboard) |
| 수집 | Wazuh agent 4.14.9 (macOS arm64) |
| 실행 환경 | Mac mini M4 (arm64), OrbStack |

## 진행 단계

| 단계 | 내용 | 상태 |
| --- | --- | --- |
| P0 | WAF(DetectionOnly) + Wazuh 베이스라인, 감사 로그 → alert 전 구간 확인 | 완료 |
| P0.5 | 보호 대상 서비스 개발, 앱 보안 이벤트 수집, 인증 공격 상관분석 | 완료 |
| P1 | 정상 트래픽 기준 오탐 수집·튜닝 | 완료 |
| P2 | 경로 탐색 가상 패치, 차단 모드 전환 | 완료 |
| P3 | 인증·API 공격 탐지 확장, 클라이언트 원 IP 보존 | 예정 |
| P4 | 대시보드·주간 리포트·Playbook, MITRE ATT&CK 매핑 정리 | 예정 |
| P5 | 오탐 후보 분류·리포트 생성 자동화 | 예정 |

## 주요 실측 결과

| 단계 | 검증 | 결과 |
| --- | --- | --- |
| P0 | SQLi 테스트 요청 | CRS 942100 탐지 → Wazuh 100201 alert(MITRE T1190) |
| P0.5 | 같은 출발지에서 두 계정 로그인 실패 10회 | 개별 실패(100301), 계정 잠금 2건(100303), 상관분석 1건(100302, 8회/120초) |
| P1 | 특수문자 포함 정상 트래픽 | 실질 오탐은 920350(숫자 IP Host) 1종. 도메인 Host 접속으로 해소, 룰 비활성 없음 |
| P1 | 역검증 | 도메인 Host는 920350 0건, IP Host는 계속 탐지 |
| P2 | 차단 모드 + CRS만 | CRS까지 도달한 경로 탐색 요청 403, 앱 미도달 |
| P2 | 차단 모드 + 가상 패치 | 같은 요청 403, 감사 로그 룰 ID는 가상 패치(1000100)만 기록 |
| P2 | 차단 모드 정상 트래픽 14건 | 200 8건, 201 6건, 403 0건 |

## 탐지 룰

**WAF (ModSecurity)**

| ID | 내용 | 파일 |
| --- | --- | --- |
| 1000100 | `/files/` 경로 탐색 가상 패치, phase 1 즉시 403 | `waf/conf/modsecurity-override.conf` |

**Wazuh**

| ID | level | 내용 | 파일 |
| --- | --- | --- | --- |
| 100200 | 3 | ModSecurity 감사 이벤트 | `wazuh/rules/panoptes_rules.xml` |
| 100201 | 6 | CRS SQLi(942xxx) 매칭, T1190 | 〃 |
| 100210 | 7 | CRS 경로 탐색·LFI(930xxx) 매칭, T1083 | `wazuh/rules/panoptes_waf_vpatch_rules.xml` |
| 100211 | 10 | 가상 패치 적중(1000100), T1083 | 〃 |
| 100300 | 0 | 앱 접근 로그(알림 없음) | `wazuh/rules/panoptes_app_rules.xml` |
| 100301 | 5 | 로그인 실패, T1110 | 〃 |
| 100302 | 10 | 같은 IP 로그인 실패 8회/120초(브루트포스·크리덴셜 스터핑), T1110 | 〃 |
| 100303 | 10 | 계정 잠금, T1110 | 〃 |
| 100304 | 6 | 권한 거부(소유자·role), T1190 | 〃 |
| 100305 | 9 | 같은 IP 권한 거부 6회/60초(열거·IDOR 탐색), T1190 | 〃 |
| 100306 | 5 | 잘못된 API 키, T1110 | 〃 |
| 100307 | 5 | 업로드 거부 | 〃 |
| 100308 | 7 | 앱 경로 탐색 차단, T1083 | 〃 |

## 보호 대상 서비스: panoptes-shop

가상의 소규모 쇼핑 서비스입니다. 기능 자체보다 탐지할 이벤트가 로그로 남는 것이 목적입니다.

| 영역 | 엔드포인트 | 보안 이벤트 |
| --- | --- | --- |
| 회원 | `/auth/signup`, `/auth/login`, `/auth/logout` | `auth.login.success`, `auth.login.failure`, `auth.lockout` |
| 주문 | `/orders`, `/orders/{id}` (본인 주문만) | `authz.denied` |
| 관리자 | `/admin/users` (admin만) | `authz.denied` |
| 파트너 API | `/partner/products` (`X-API-Key`) | `apikey.invalid` |
| 파일 | `/me/avatar`, `/files/{path}` | `upload.rejected`, `path.traversal` |

- 비밀번호는 argon2, API 키는 SHA-256 해시로만 저장합니다.
- 비밀번호·세션 값·API 키 원문은 로그에 남기지 않습니다(테스트로 확인).
- 시드 계정과 API 키는 검증 전용 값입니다(`app/seed.py`).

## 디렉터리

```
app/                 보호 대상 서비스(FastAPI), Dockerfile
tests/               pytest (기능·보안 동작·로그 위생)
waf/conf/            ModSecurity override(가상 패치)
wazuh/groups/        그룹 agent.conf (수집 경로)
wazuh/rules/         Wazuh 커스텀 룰
scripts/             트래픽·검증 스크립트
docs/                단계별 구성·검증 기록
intents/             목표·범위(intent), 서비스 명세(spec)
compose.yaml         profiles: core(waf·app·db), echo(P0 회귀용)
```

## 실행

사전 준비: Docker 엔진(OrbStack 또는 Docker Desktop), Python 3, Wazuh single-node 스택([wazuh-docker](https://github.com/wazuh/wazuh-docker) v4.14.9, 별도 디렉터리).

```bash
cp .env.example .env
# .env: WAF_TAG(다이제스트), SESSION_SECRET(openssl rand -hex 32), MODSEC_RULE_ENGINE 설정
mkdir -p logs/modsec logs/app
docker compose --profile core up -d --build
docker compose --profile core ps
```

Wazuh 룰·그룹 설정 배포:

```bash
for f in wazuh/rules/*.xml; do
  docker cp "$f" single-node-wazuh.manager-1:/var/ossec/etc/rules/
done
docker cp wazuh/groups/panoptes-waf/agent.conf single-node-wazuh.manager-1:/var/ossec/etc/shared/panoptes-waf/agent.conf
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

`agent.conf`의 로그 경로는 실행 환경의 절대 경로에 맞게 수정해야 합니다.

## 스크립트

| 스크립트 | 용도 |
| --- | --- |
| `scripts/p0_smoke.py` | P0 베이스라인 확인(DetectionOnly 기준) |
| `scripts/normal_traffic.py` | 정상 사용 흐름 생성, 오탐 수집·차단 모드 영향 확인 |
| `scripts/traversal_probe.py` | `/files` 경로 탐색 가상 패치 검증(본인 검증 환경 대상) |

테스트 트래픽은 본인이 구성한 검증 환경에만 보냅니다.

## 설계 원칙

- 로그 우선: 탐지할 상황과 이벤트 코드를 먼저 정하고 기능을 그 기준에 맞춥니다.
- 룰 비활성 지양: 오탐은 룰을 끄기보다 원인(예: IP 직접 접속)을 제거해 해소합니다. 예외가 필요하면 경로·출발지 단위로 가장 좁게 둡니다.
- 단계 분리 검증: 효과가 섞이지 않도록 조건을 하나씩 바꿔 확인합니다(예: CRS만 → 가상 패치 추가).
- 원본 로그 기준 판단: SIEM 알림만 보지 않고 감사 로그·앱 로그·nginx 접근 로그로 직접 확인합니다.

## 알려진 제약

| 항목 | 내용 |
| --- | --- |
| 클라이언트 IP | OrbStack 포트 포워딩으로 WAF가 받는 클라이언트 IP가 게이트웨이 주소로 바뀝니다. IP 단위 탐지(P3) 전에 원 IP 보존이 필요합니다. |
| 외부 클라이언트 | 다른 호스트에서의 접속 검증은 네트워크 구성 문제로 미완료입니다. |
| 포트 노출 | Wazuh 대시보드·indexer·API가 호스트의 모든 인터페이스에 열려 있습니다. |
| 감사 로그 범위 | `RelevantOnly` 설정이라 룰 매칭이 없는 정상 2xx 요청은 감사 로그에 남지 않습니다. |

## 문서

| 문서 | 내용 |
| --- | --- |
| `intents/panoptes-detect/intent.md` | 목표, 범위, 단계별 완료 기준 |
| `intents/panoptes-detect/spec.md` | 보호 대상 서비스 명세 |
| `docs/p0-setup.md` | P0 베이스라인 구성·트러블슈팅 |
| `docs/p05-app.md` | 보호 대상 서비스 구성 |
| `docs/p05-wazuh-app-rules.md` | 앱 로그 수집, 인증 공격 상관분석 |
| `docs/p1-tuning.md` | 오탐 튜닝 |
| `docs/p2-virtual-patch.md` | 가상 패치, 차단 모드 전환 |
| `docs/references.md` | 참고 자료 |

블로그 연재: [panoptes-detect P0 — ModSecurity CRS 감사 로그를 Wazuh alert로 잇는 베이스라인](https://parkjongmin-ddam.github.io/infra/security/panoptes-p0-baseline/)
