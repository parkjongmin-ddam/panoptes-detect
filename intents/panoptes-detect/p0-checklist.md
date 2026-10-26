# P0 베이스라인 체크리스트 — panoptes-detect

목표: 정상 요청이 WAF(DetectionOnly)를 거쳐 응답되고, WAF 감사 로그가 Wazuh에서 조회되는 상태.
원칙: 보호 대상은 단순한 것부터. P0는 테스트 백엔드 1개로 끝내고, ADFS/WAP 연결은 P1에서 한다.

## 구성도
```
[Win11_user VM .111] --HTTP--> [Mac mini .138 :8080  WAF(ModSecurity+CRS)] --> [백엔드 컨테이너]
                                         |
                                  감사 로그(JSON, 파일)
                                         v
                    [Mac mini Wazuh agent] --> [Wazuh single-node(Docker): manager/indexer/dashboard]
```

## 0. 사전 점검 (Mac mini)
- [ ] 랩 통신 확인
  - `ping -c 3 192.168.219.191` (DC01)
  - `nc -vz 192.168.219.240 443` (ADFS VIP, P1 대비)
- [ ] Docker Desktop 설치·실행, `docker info | grep -i -E 'arch|memory'`로 aarch64 확인
- [ ] Docker Desktop 리소스: Memory 12GB 이상, Disk 60GB 이상 할당 (Wazuh indexer + WAF + 백엔드 기준 여유치)
- [ ] macOS 방화벽이 켜져 있으면 Docker 수신 허용 여부 확인
- [ ] 작업 폴더: `~/lab/panoptes-detect/{waf,wazuh,backend,logs}`

## 1. 테스트 백엔드
- [ ] 요청을 그대로 반사하는 단순 백엔드 1개 기동 (예: `mendhak/http-https-echo` 또는 adfs-sample-py Flask 앱 중 택1)
  - 1차 권장: echo 계열 — 헤더·본문이 그대로 보여 WAF 경유 여부와 X-Forwarded-For 확인이 쉬움
- [ ] 백엔드는 외부 포트를 열지 않고 Docker 네트워크(`wdo-net`) 내부에서만 노출

## 2. WAF (owasp/modsecurity-crs:nginx)
- [ ] 이미지 pull 시 태그를 날짜 포함 고정 태그로 기록 (rolling `nginx` 태그 대신 재현성 확보)
- [ ] 주요 환경변수 (변수명은 pull 시점 README로 재확인)
  - `BACKEND=http://backend:8080` (백엔드 컨테이너명·포트에 맞춤)
  - `MODSEC_RULE_ENGINE=DetectionOnly`
  - `PARANOIA=1`, `BLOCKING_PARANOIA=1` (베이스라인은 기본값)
  - `MODSEC_AUDIT_LOG_FORMAT=JSON`
  - `MODSEC_AUDIT_LOG=/var/log/modsec/audit.log` → 호스트 `~/lab/panoptes-detect/logs`에 bind mount
  - `MODSEC_AUDIT_ENGINE=RelevantOnly` (룰 매칭·4xx/5xx만 기록, 로그량 억제)
- [ ] 포트: 호스트 8080 → 컨테이너 8080 (HTTP). TLS(8443)는 P1에서 ADFS 연결 시 추가
- [ ] compose 파일로 백엔드·WAF를 함께 정의하고 저장소에 커밋

검증
- [ ] Win11_user에서 `curl -i http://192.168.219.138:8080/` → 200, 백엔드 응답 확인
- [ ] 탐지 확인용 요청: `curl -i "http://192.168.219.138:8080/?id=1%27%20OR%20%271%27=%271"`
  - DetectionOnly이므로 200이 정상, 대신 audit.log에 CRS 942xxx(SQLi) 룰 매칭 기록이 남아야 함
- [ ] `docker logs waf`에서 nginx 에러·ModSecurity 로드 오류 없음

## 3. Wazuh single-node (Docker)
- [ ] `git clone https://github.com/wazuh/wazuh-docker.git -b <안정 버전 태그>` → `single-node/`
- [ ] 인증서 생성: `docker compose -f generate-indexer-certs.yml run --rm generator`
- [ ] 기본 계정 비밀번호 변경 후 `docker compose up -d`
- [ ] 대시보드 `https://192.168.219.138` 접속 확인 (자체 서명 경고는 정상)
- [ ] 리소스 확인: `docker stats`로 indexer 메모리 사용량 기록

## 4. 로그 수집
- [ ] Mac mini에 Wazuh agent(macOS 패키지) 설치, manager 주소 `127.0.0.1` 등록
- [ ] agent `ossec.conf`에 localfile 추가
  ```xml
  <localfile>
    <log_format>json</log_format>
    <location>/Users/<user>/lab/panoptes-detect/logs/audit.log</location>
  </localfile>
  ```
- [ ] agent 재시작 후 대시보드 Agents 목록에 Active 표시 확인
- [ ] JSON 필드가 그대로 인덱싱되는지 확인 — 기본 디코더로 alert가 안 생기면 manager에 ModSecurity용 커스텀 룰(최소 1개: transaction 존재 시 level 5 alert) 추가
  - 이 커스텀 룰 작성이 P0의 유일한 "개발" 항목. 파일은 저장소 `wazuh/rules/local_modsec.xml`로 관리

검증
- [ ] 2단계의 SQLi 테스트 요청 1회 → Wazuh Discover/Threat Hunting에서 해당 이벤트 조회
- [ ] 이벤트에서 client IP(.111), URI, 룰 ID(942xxx) 필드 확인

## 5. 완료 기준 (intent P0)
- [ ] 정상 요청 WAF 경유 200 응답
- [ ] 탐지 요청 1건이 audit.log → Wazuh까지 도달, 필드 조회 가능
- [ ] compose·설정·커스텀 룰 파일이 저장소에 커밋됨
- [ ] 설치 절차와 발생 이슈를 `docs/p0-setup.md`에 기록 (블로그 1편 분량)

## 6. 보류 항목 (P1 이후)
- WAP01 구성 상태 확인 결과에 따라 ADFS 앞단 배치 방식 결정
- TLS 종료: azlab ISCA01에서 WAF용 서버 인증서 발급, 클라이언트는 기존 GPO 체인 신뢰 활용
- sts.azlab.istn.co.kr 이름을 WAF로 향하게 하는 방식(테스트 클라이언트 hosts 파일 우선, DNS 변경은 후순위)
