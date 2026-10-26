# intent: panoptes-detect (v2)

- 저장소: panoptes-detect (구 작업명 web-detection-ops)

## 1. 목적
- 직접 개발한 웹·API 서비스를 보호 대상으로, WAF·로그 수집·탐지 룰·리포트·Playbook까지 탐지 운영(Detection Operations) 흐름을 처음부터 구성한다.
- 인증 설계(세션·토큰·계정 잠금)와 로그 설계를 포함해 IAM 경력과 웹 보안 탐지 역량을 연결하는 포트폴리오를 만든다.

## 2. 배경
- 참고 공고: 쿠팡 Detection Operations, Security Engineer (Web Security)
  - 업무: WAF 정/오탐 분석·미탐 개선, Bot 탐지/차단, DDoS 대응, CVE 대응, SIEM/Access 로그 분석·리포트, SOP·Playbook, Flow 자동화, API Security 이벤트 대응
  - 우대: OWASP, MITRE ATT&CK, SIEM/SQL 분석, Python, 클라우드, CDN 보안
- 소재 출처: 보안프로젝트 채널 커뮤니티 게시물(2026-10 기준 최근 120건 중 선별)
  - PHP2Shell(CVE-2026-109618/109619), API 인증 미흡 유출 사고, KrCERT 웹·API 점검 권고, API 키 노출 사고, 크리덴셜 스터핑 정황
- v1 대비 변경(2026-10-26)
  - 기존 azlab(AD·ADFS·SQL·PKI)은 사용하지 않음. 프로젝트 전용 환경을 새로 구성
  - 보호 대상을 ADFS에서 신규 개발 서비스로 변경
  - 사유: Host 메모리 여유 부족(약 4.8GB), ADFS NLB 멀티캐스트·게이트웨이 오설정 등 기존 랩 정비 부담, 앱 로그를 탐지 목적에 맞게 직접 설계 가능

## 3. 범위
- 포함
  - 신규 서비스(웹·REST API, 인증 포함) 개발
  - 리버스 프록시 WAF(nginx + ModSecurity v3 + OWASP CRS)
  - SIEM(Wazuh single-node)
  - 탐지 룰, 가상 패치 룰, 오탐 예외 룰, 리포트, Playbook/SOP, MITRE ATT&CK 매핑
- 제외
  - 기존 azlab 변경
  - 모바일 앱 보안, 리버싱, 악성코드 분석
  - 유료 클라우드 WAF 상시 운영, 외부 인터넷 노출
- 선택(후순위)
  - 경계 방화벽 계층(OPNsense 재설치 또는 컨테이너 방화벽)

## 4. 제약
- 테스트 트래픽은 본 프로젝트 환경에만 발생시킨다.
- 무과금 원칙
- CVE 세부 내용은 착수 시점에 공식 공지·NVD로 재확인
- 공개 전 식별 정보 마스킹
- 이미지·스크립트는 amd64·arm64 양쪽에서 동작해야 한다.

## 5. 실행 환경
| 구분 | Mac mini M4 (32GB, 192.168.219.138) | Windows PC (D:\Project) |
|---|---|---|
| 역할 | 상시 실행 환경 | 개발·단위 테스트, 외부 클라이언트 |
| 실행 대상 | 전체 스택: waf, app, db, siem | app·db만(개발용), Wazuh 미실행 |
| 아키텍처 | arm64 | amd64 |
| 트래픽 | 수신 | Mac 스택으로 요청 발생(별도 호스트 IP로 로그에 기록) |

- 단일 git 저장소, 단일 compose 파일 + profile로 구분
  - `core`: waf, app, db
  - `siem`: Wazuh (Mac에서만)
- Windows 메모리 여유가 작으므로 Windows에서는 `core`만, 필요 시 app을 venv로 직접 실행

## 6. 아키텍처
```
[클라이언트: Windows PC / Mac 로컬]
        |  HTTP(S)
[waf]  nginx + ModSecurity v3 + CRS      (network: edge, dmz)
        |  X-Request-ID 전달
[app]  신규 서비스 (FastAPI)            (network: dmz, internal)
        |
[db]   PostgreSQL                        (network: internal)

[siem] Wazuh single-node — waf 감사 로그, app 구조화 로그 수집
```
- 외부 포트는 waf만 공개. app·db는 내부 네트워크 전용
- waf가 요청마다 ID를 부여하고 app이 같은 ID로 로그를 남겨 WAF 이벤트와 앱 이벤트를 연결

## 7. 단계와 완료 기준
| 단계 | 내용 | 완료 기준 |
|---|---|---|
| P0 베이스라인 | waf(DetectionOnly) + echo 백엔드 + Wazuh, 로그 수집 | 정상 요청 200, 탐지 요청 1건이 Wazuh에서 조회됨 |
| P0.5 서비스 MVP | 신규 앱 MVP(spec.md 기준), 구조화 로그, waf 뒤 배치 | 기능 테스트 통과, waf 경유 요청의 Request ID가 waf·app 로그 양쪽에서 일치 |
| P1 정/오탐 튜닝 | 정상 사용 시나리오(로그인, JSON API, 파일 업로드 등) 오탐 분석, 예외 룰·Paranoia Level 조정 | 정상 시나리오 오탐 0건, 예외 근거 문서화 |
| P2 CVE 대응 | 공개 CVE 1~2건 대상 가상 패치 룰 작성·검증 | 차단 모드에서 테스트 요청 차단·정상 요청 통과, 근거 기록 |
| P3 API·인증 이벤트 | 로그인 실패 급증, 객체 권한 위반 시도, 응답 내 비밀값 노출 탐지 룰 | 시나리오별 탐지 이벤트 발생, 앱 계정 잠금과 waf 탐지 연계 확인 |
| P4 SIEM·리포트 | 대시보드, 주간 리포트, ATT&CK 매핑, Playbook/SOP | 시나리오별 Playbook 1건 이상, 리포트 1회분 |
| P5 자동화 | 오탐 후보 분류·리포트 생성 스크립트 | 스크립트 실행으로 리포트 재현 가능 |

## 8. 산출물
- 저장소: compose, waf 설정, Wazuh 룰, 앱 소스, 테스트
- 구성 문서, 룰셋 및 근거, 분석 기록, Playbook/SOP
- 블로그 연재(ddamnote)

## 9. 열린 질문
- 저장소 공개 여부(초기 비공개)
- 경계 방화벽 계층 도입 여부(P4 이후 재검토)
- winserver-monitor-agent 보안 확장과 룰 체계 연계 여부
