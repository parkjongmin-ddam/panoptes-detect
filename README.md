# panoptes-detect

직접 개발한 웹·API 서비스를 보호 대상으로 WAF, 로그 수집, 탐지 룰, 리포트, Playbook까지 탐지 운영 흐름을 구성하는 홈랩 프로젝트.

- 목표·범위: `intents/panoptes-detect/intent.md`
- 서비스 명세: `intents/panoptes-detect/spec.md`
- 현재 단계: P0 베이스라인 (`intents/panoptes-detect/p0-checklist.md`)

## 구성 (P0)

```
client → waf (nginx + ModSecurity v3 + OWASP CRS, DetectionOnly) → backend (echo)
                 └─ logs/modsec/audit.log (JSON) → Wazuh
```

## 실행

```bash
cp .env.example .env
mkdir -p logs/modsec
docker compose --profile core up -d
python3 scripts/p0_smoke.py
```

## 실행 환경

| 호스트 | 역할 | profile |
|---|---|---|
| Mac mini (arm64) | 상시 실행, SIEM | core, siem |
| Windows PC (amd64) | 개발, 외부 클라이언트 | core |

## 고정 버전 (P0 검증 기준, 2026-10-26)

| 구성요소 | 값 |
|---|---|
| WAF 이미지 | owasp/modsecurity-crs:nginx@sha256:7698c48a41a43138ae317feeec964d1515b861cc1d9e50617bc1cdfe9f314e1d |
| OWASP CRS | 4.30.0 |
| nginx | 1.30.6 (unprivileged) |
| 컨테이너 엔진 | OrbStack (aarch64) |
