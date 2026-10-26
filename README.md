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
