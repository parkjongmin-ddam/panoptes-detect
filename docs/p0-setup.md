# P0 베이스라인 구성 기록

- 일자: 2026-10-26
- 환경: Mac mini M4 (arm64), OrbStack
- 결과: 완료 — 요청 → WAF → 감사 로그 → Wazuh agent → manager 룰 → alert 전 구간 확인

## 1. 구성 요소와 버전

| 구성 요소 | 값 |
|---|---|
| WAF 이미지 | owasp/modsecurity-crs:nginx@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d |
| ModSecurity / connector | v3.0.17 / ModSecurity-nginx v1.0.4 |
| OWASP CRS | 4.30.0 (Paranoia Level 기본값 1, DetectionOnly) |
| 백엔드 | mendhak/http-https-echo (P0 임시) |
| Wazuh | 4.14.9 single-node Docker (manager, indexer, dashboard) |
| Wazuh agent | 4.14.9 macOS arm64, 이름 macmini-waf, ID 001 |

## 2. 데이터 흐름

```
client → waf:8080 → backend
          └ logs/modsec/audit.log (JSON, RelevantOnly)
               └ Wazuh agent (그룹 panoptes-waf의 agent.conf로 수집 경로 배포)
                    └ manager: json 디코더 → panoptes_rules.xml → alerts
```

- 수집 경로는 agent 로컬 설정이 아니라 manager의 그룹 설정(`wazuh/groups/panoptes-waf/agent.conf`)으로 배포
- 룰: `wazuh/rules/panoptes_rules.xml`
  - 100200 (level 3): ModSecurity 감사 이벤트 (`transaction.producer.modsecurity`)
  - 100201 (level 6): CRS 942xxx(SQLi) 포함, MITRE T1190

## 3. 검증 결과

`scripts/p0_smoke.py` 실행 후 alert 내역

| rule.id | level | uri | 원인 |
|---|---|---|---|
| 100200 | 3 | /healthz | 920350(Host가 숫자 IP)만 매칭 |
| 100200 | 3 | / | 920350만 매칭 |
| 100201 | 6 | /?id=1' OR '1'='1 | 942100(libinjection SQLi), 949110(이상 점수 8 ≥ 5) |

- `wazuh-logtest`로 디코딩·룰 매칭 단계별 확인
- agent 로그: 그룹 할당 후 약 1분 내 `Agent is reloading due to shared configuration changes` → `Analyzing file: .../audit.log`

## 4. 트러블슈팅

| 증상 | 원인 | 조치 |
|---|---|---|
| unzip이 "filename not matched"로 아무것도 풀지 않음 | zsh 대화형 모드는 `#`을 주석으로 처리하지 않아 주석 문구가 인자로 전달됨 | 명령에 줄 끝 주석 사용 금지. 필요 시 `setopt interactivecomments` |
| docker 명령이 `.orbstack/run/docker.sock` 연결 실패 | docker context가 OrbStack인데 OrbStack 미실행 | `open -a OrbStack` |
| smoke 테스트 Connection reset | WAF 기동 직후(health: starting) 요청 | 스크립트에 `/healthz` 200 대기(최대 30초) 추가 |
| Wazuh 인증서 생성 중 `root-ca-manager.pem` Permission denied, 이후 마운트 경로 mkdir 실패 | generator가 인증서 폴더 소유자를 바꾼 뒤 마지막 복사 단계 실패 | `root-ca.pem/.key`를 `root-ca-manager.pem/.key`로 직접 복사, 소유자 복원 후 기동 |
| 대시보드에서 admin 비밀번호 변경 시 `Resource 'admin' is reserved` | admin은 예약 계정이라 UI·API로 변경 불가 | `internal_users.yml` 해시 교체 + compose `INDEXER_PASSWORD` 변경 + `securityadmin.sh` 적용 |
| 비밀번호 변경 후 새 비밀번호로 401 | `hash.sh`는 확인 입력이 없어 오타가 그대로 해시됨(해시 대조 실패로 확인) | `htpasswd -nBC 12 admin`(2회 입력)으로 해시 생성 후 재적용 |
| `launchctl bootstrap` 두 번째 실행 시 `Input/output error(5)` | 이미 등록된 서비스 중복 등록 | 무시. `launchctl print system/com.wazuh.agent`로 running 확인 |

## 5. 확인된 사항과 열린 항목

- Wazuh JSON 디코더는 객체 배열(`transaction.messages`)을 개별 필드로 펼치지 않고 문자열로 저장함 → 룰 ID 조건은 원문 정규식으로 작성
- 기본 설정에서는 룰에 매칭된 이벤트만 alert로 저장됨(룰 추가 전 alert 0건 확인)
- [열림] WAF 로그의 `client_ip`가 실제 클라이언트(127.0.0.1)가 아니라 OrbStack 게이트웨이(192.168.107.1)로 기록됨. Windows PC 등 외부 호스트에서의 요청도 같은지 확인 필요. IP 기반 탐지(P3) 전에 원 IP 보존 방법 정리
- [열림] 헬스체크·정상 요청도 920350 때문에 alert(level 3)가 됨 → P1 정/오탐 튜닝 첫 사례
- [열림] Wazuh 대시보드(443)·indexer(9200)·API(55000)가 Mac의 모든 인터페이스에 열려 있음. 필요 시 127.0.0.1 바인딩 검토

## 6. 실습 종료 시 agent 제거

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.wazuh.agent.plist
sudo /bin/rm -r /Library/Ossec
sudo /bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist
sudo /bin/rm -rf /Library/StartupItems/WAZUH
sudo /usr/bin/dscl . -delete "/Users/wazuh"
sudo /usr/bin/dscl . -delete "/Groups/wazuh"
sudo /usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent
```
