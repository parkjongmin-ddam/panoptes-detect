"""정상 사용 트래픽 생성기 (P1 오탐 분석용).

공격이 아닌 정상 사용 흐름을 WAF 경유로 보낸다. 이 중 WAF(CRS) 룰에 매칭되는
요청이 오탐 후보다. 공격 페이로드는 포함하지 않는다.

실제 서비스처럼 도메인 Host로 접속한다(숫자 IP Host는 CRS 920350 유발).
urllib은 Host 헤더를 URL 호스트로 덮어쓰므로 http.client로 직접 보낸다.

사용:
  python3 scripts/normal_traffic.py                       # 127.0.0.1:8080, Host=shop.panoptes.lab
  python3 scripts/normal_traffic.py 192.168.219.138 8080
  HOST=127.0.0.1 python3 scripts/normal_traffic.py        # 숫자 IP Host로 보내 오탐 재현
"""
import http.client
import json
import os
import sys

ADDR = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
HOST = os.getenv("HOST", "shop.panoptes.lab")  # 실제 서비스 도메인 역할


def req(method, path, body=None, headers=None, cookie=None):
    conn = http.client.HTTPConnection(ADDR, PORT, timeout=5)
    h = {"Host": HOST, "User-Agent": "panoptes-normal/1.0"}
    data = None
    if body is not None:
        data = json.dumps(body)
        h["Content-Type"] = "application/json"
    if cookie:
        h["Cookie"] = cookie
    if headers:
        h.update(headers)
    try:
        conn.request(method, path, body=data, headers=h)
        resp = conn.getresponse()
        set_cookie = resp.getheader("Set-Cookie")
        resp.read()
        return resp.status, set_cookie
    finally:
        conn.close()


def main():
    n = 0
    req("GET", "/health"); n += 1
    req("GET", "/"); n += 1

    _, cookie = req("POST", "/auth/login",
                    {"username": "alice", "password": "alice-lab-pw"})
    n += 1
    sess = cookie.split(";")[0] if cookie else None

    if sess:
        req("GET", "/me", cookie=sess); n += 1
        req("GET", "/orders", cookie=sess); n += 1
        for item in [
            "USB-C 케이블 2m",
            "O'Brien 머그컵",          # 아포스트로피: SQLi 룰 오탐 유발 가능
            "모니터 (27\" 4K)",
            "key=value 메모",
            "1+1 행사 상품",
            "C# 책",
        ]:
            req("POST", "/orders", {"item": item, "qty": 1}, cookie=sess); n += 1
        req("GET", "/orders", cookie=sess); n += 1
        req("POST", "/auth/logout", cookie=sess); n += 1

    req("GET", "/partner/products",
        headers={"X-API-Key": "panoptes-partner-lab-key"}); n += 1

    print(f"정상 트래픽 {n}건 전송 완료 → {ADDR}:{PORT} (Host={HOST or '없음'})")
    print("다음: Wazuh에서 이 시간대의 WAF 매칭(rule.groups:modsecurity)을 확인")


if __name__ == "__main__":
    main()
