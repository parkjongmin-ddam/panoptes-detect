# P0.5 앱 로그 수집 + 인증 공격 상관분석

- 일자: 2026-10-27
- 환경: Mac mini M4 (arm64), OrbStack, Wazuh 4.14.9
- 결과: 완료 — 앱 보안 이벤트가 Wazuh로 수집되고, 개별 탐지 + 상관분석 알림까지 동작

## 1. 목적

앞 단계(P0)에서 WAF 감사 로그만 수집했다. panoptes-shop 앱의 보안 이벤트(로그인 실패, 계정 잠금, 권한 거부 등)를 Wazuh로 수집하고, 단일 룰로는 불가능한 "여러 요청을 묶어 판단하는" 상관분석 탐지를 구성한다.

## 2. 로그 전달 방식

- 앱 접근/보안 로그를 stdout과 파일(`/var/log/panoptes/app.log`) 양쪽에 기록
  - 파일 경로는 `APP_LOG_FILE` 환경변수. 쓰기 실패 시 stdout만 사용(fallback)
  - compose에 `./logs/app:/var/log/panoptes` 마운트. 앱은 비특권(uid 10001)이라 호스트 디렉터리 쓰기 권한 필요
- 수집은 P0 구조 재사용: manager의 그룹 설정(`agent.conf`)에 app.log localfile 추가
  - WAF 로그와 구분 위해 `label key="panoptes_source"` = app / modsecurity

## 3. 룰 (100300번대)

| 룰 | level | 조건 | MITRE |
|---|---|---|---|
| 100300 | 0 | logger=panoptes.app (기본 접근로그, 자체 알림 안 함) | - |
| 100301 | 5 | event=auth.login.failure | T1110 |
| 100302 | 10 | 같은 client_ip의 100301이 8회/120초 (브루트포스·크리덴셜 스터핑) | T1110 |
| 100303 | 10 | event=auth.lockout | T1110 |
| 100304 | 6 | event=authz.denied | T1190 |
| 100305 | 9 | 같은 client_ip의 100304가 6회/60초 (열거·IDOR 탐색) | T1190 |
| 100306 | 5 | event=apikey.invalid | T1110 |
| 100307 | 5 | event=upload.rejected | - |

- 기본 접근로그(100300)는 level 0이라 수집은 되나 알림은 보안 이벤트에만 발생
- 상관분석(100302/100305)은 `if_matched_sid` + `same_field` + frequency/timeframe

## 4. 검증 결과

- 서로 다른 계정(alice/bob)으로 로그인 실패 10회 발생 → alert 확인
  - 100301 개별 실패 7건
  - 100303 계정 잠금 2건 (임계값 5회 도달)
  - **100302 브루트포스 1건 발생** — 같은 IP의 실패 8건을 frequency=8로 묶어 상관분석 성공 (previous_output에 묶인 이벤트 확인)
- logtest로 단계별 매칭 확인(Phase 3: 정상요청→100300 level 0, 실패→100301)

## 5. 발견·조정

- Wazuh json 디코더가 로그의 `user` 필드를 자동으로 `dstuser`로 매핑 → 룰 description의 `$(user)`가 비어 나옴. `$(dstuser)`로 수정해 사용자명 표시 복구
- `same_field`는 `client_ip`(data.client_ip)로 정상 동작 — 버전별 차이 우려했으나 4.14.9에서 문제없음
- 앱이 보내는 `attempts` 필드로 실패 누적 추이도 alert에 보존됨

## 6. 의의

- WAF(요청 단위)와 앱(비즈니스 로직 단위) 로그가 request_id로 연결되어 양쪽에서 조회 가능
- 단일 WAF 룰로는 불가능한 "분산된 요청의 패턴 탐지"를 SIEM 상관분석으로 구현 — 쿠팡 공고의 "Usecase/Playbook 생성", "SIEM 분석" 요건과 직접 연결

## 7. 다음 단계

- P1: 정/오탐 튜닝 (WAF 920350 등 랩 환경 오탐 정리)
- P3: 인증 공격 탐지 확장 (지금의 상관분석을 기반으로 시나리오 추가), client_ip 원 IP 보존
