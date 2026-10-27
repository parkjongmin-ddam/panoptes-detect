"""기능·보안 동작·로그 검증 (spec 6절).

로그는 stdout JSON이므로 capsys로 캡처해 event 코드를 확인한다.
"""
import json

from seed import SEED_API_KEY


def _events(capsys):
    """캡처된 stdout에서 app 로그 레코드만 파싱."""
    out = capsys.readouterr().out
    recs = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            recs.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return recs


def _login(client, username, password):
    return client.post("/auth/login", json={"username": username, "password": password})


# ---- 기능 ----

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_signup_login_logout(client, capsys):
    assert client.post("/auth/signup", json={"username": "carol", "password": "carol-pw"}).status_code == 201
    r = _login(client, "carol", "carol-pw")
    assert r.status_code == 200 and r.cookies.get("panoptes_session")
    assert client.get("/me").json()["username"] == "carol"
    assert client.post("/auth/logout").status_code == 200
    # 로그아웃 후 인증 필요 엔드포인트는 401
    assert client.get("/me").status_code == 401
    assert any(e.get("event") == "auth.login.success" for e in _events(capsys))


def test_order_create_and_list(client):
    _login(client, "alice", "alice-lab-pw")
    assert client.post("/orders", json={"item": "cable", "qty": 3}).status_code == 201
    items = [o["item"] for o in client.get("/orders").json()]
    assert "cable" in items
    client.post("/auth/logout")


# ---- 보안 동작 ----

def test_cross_user_order_is_denied(client, capsys):
    # alice의 주문 id를 확보
    _login(client, "alice", "alice-lab-pw")
    oid = client.post("/orders", json={"item": "secret", "qty": 1}).json()["id"]
    client.post("/auth/logout")
    _events(capsys)  # 비우기

    # bob이 alice 주문 조회 시도 → 404 + authz.denied 로그
    _login(client, "bob", "bob-lab-pw")
    r = client.get(f"/orders/{oid}")
    assert r.status_code == 404
    evs = _events(capsys)
    assert any(e.get("event") == "authz.denied" and e.get("reason") == "owner" for e in evs)
    client.post("/auth/logout")


def test_admin_only(client, capsys):
    _login(client, "bob", "bob-lab-pw")
    assert client.get("/admin/users").status_code == 403
    assert any(e.get("event") == "authz.denied" for e in _events(capsys))
    client.post("/auth/logout")

    _login(client, "admin", "admin-lab-pw")
    assert client.get("/admin/users").status_code == 200
    client.post("/auth/logout")


def test_lockout(client, capsys):
    client.post("/auth/signup", json={"username": "dave", "password": "dave-pw"})
    _events(capsys)
    # 임계값(3)까지 실패 → 잠금
    for _ in range(3):
        _login(client, "dave", "wrong")
    evs = _events(capsys)
    assert any(e.get("event") == "auth.lockout" for e in evs)
    # 잠긴 동안은 올바른 비번도 423
    assert _login(client, "dave", "dave-pw").status_code == 423


def test_api_key(client, capsys):
    # 키 없음
    assert client.get("/partner/products").status_code == 401
    # 잘못된 키 → apikey.invalid
    assert client.get("/partner/products", headers={"X-API-Key": "nope"}).status_code == 401
    assert any(e.get("event") == "apikey.invalid" for e in _events(capsys))
    # 올바른 키
    r = client.get("/partner/products", headers={"X-API-Key": SEED_API_KEY})
    assert r.status_code == 200 and len(r.json()) >= 1


def test_avatar_rejects_bad_type(client, capsys):
    _login(client, "alice", "alice-lab-pw")
    r = client.post("/me/avatar", files={"file": ("x.txt", b"hello", "text/plain")})
    assert r.status_code == 415
    assert any(e.get("event") == "upload.rejected" for e in _events(capsys))
    client.post("/auth/logout")


# ---- 로그 위생 ----

def test_logs_carry_request_id_and_no_secrets(client, capsys):
    _events(capsys)
    client.post("/auth/signup", json={"username": "erin", "password": "super-secret-pw"})
    _login(client, "erin", "super-secret-pw")
    recs = _events(capsys)
    app_recs = [r for r in recs if r.get("logger") == "panoptes.app"]
    assert app_recs and all("request_id" in r for r in app_recs)
    # 비밀번호 원문이 어떤 로그에도 없어야 함
    assert not any("super-secret-pw" in json.dumps(r) for r in recs)
    client.post("/auth/logout")


def test_xff_is_recorded_as_client_ip(client, capsys):
    _events(capsys)
    client.get("/health", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
    recs = _events(capsys)
    health = [r for r in recs if r.get("path") == "/health"][-1]
    assert health["client_ip"] == "203.0.113.9"
