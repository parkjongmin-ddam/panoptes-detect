"""P0 smoke test: WAF 경유 응답과 감사 로그 기록 확인 (표준 라이브러리만 사용)."""
import json, sys, time, urllib.error, urllib.request
from pathlib import Path

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
AUDIT_LOG = Path(__file__).resolve().parent.parent / "logs" / "modsec" / "audit.log"
PROBE_QUERY = "?id=1%27%20OR%20%271%27%3D%271"
MARKER = f"panoptes-p0-{int(time.time())}"
READY_TIMEOUT = 30


def get(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": MARKER})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, ConnectionError, OSError):
        return None


def wait_ready():
    deadline = time.time() + READY_TIMEOUT
    while time.time() < deadline:
        if get("/healthz") == 200:
            return True
        time.sleep(1)
    return False


def main():
    if not wait_ready():
        print(f"WAF에 연결할 수 없음: {BASE} ({READY_TIMEOUT}초 대기)")
        print("확인: docker compose --profile core ps / docker compose logs waf")
        return 1

    ok = True
    s = get("/")
    print(f"[1] 정상 요청       {s} (기대 200)")
    ok &= s == 200
    s = get("/" + PROBE_QUERY)
    print(f"[2] 탐지 유도 요청  {s} (기대 200, DetectionOnly)")
    ok &= s == 200

    if not AUDIT_LOG.exists():
        print(f"[3] 감사 로그 없음: {AUDIT_LOG}")
        return 1
    time.sleep(1)
    ids = set()
    for line in AUDIT_LOG.read_text(encoding="utf-8", errors="replace").splitlines():
        if MARKER not in line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        for m in entry.get("transaction", {}).get("messages", []):
            rid = m.get("details", {}).get("ruleId")
            if rid:
                ids.add(rid)
    sqli = sorted(i for i in ids if i.startswith("942"))
    print(f"[3] 매칭 룰 {sorted(ids) or '없음'}")
    print(f"    SQLi(942xxx) {sqli or '없음'} (기대 1개 이상)")
    ok &= bool(sqli)
    print("결과:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
