"""panoptes-detect 보호 대상 서비스 (가상 쇼핑 서비스 MVP).

보안 기본값을 지킨 정상 구현. 탐지 운영에 필요한 트래픽과 구조화 로그를 만든다.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

import security
from config import settings
from db import ApiKey, Base, Order, Product, Session, SessionLocal, User, as_aware, engine, utcnow
from logmw import AccessLogMiddleware, set_event
from seed import seed


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    with SessionLocal() as db:
        seed(db)
    yield


app = FastAPI(title="panoptes-shop", version="0.1.0", lifespan=lifespan)
app.add_middleware(AccessLogMiddleware)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---- 인증 의존성 ----

def current_user(request: Request, db: OrmSession = Depends(get_db)) -> User:
    token = request.cookies.get(settings.SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="not authenticated")
    sess = db.get(Session, token)
    if sess is None or as_aware(sess.expires_at) <= utcnow():
        raise HTTPException(status_code=401, detail="session expired")
    user = db.get(User, sess.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")
    request.state.user_id = user.id
    return user


def require_admin(request: Request, user: User = Depends(current_user)) -> User:
    if user.role != "admin":
        set_event(request, "authz.denied", reason="role", need="admin", path=request.url.path)
        raise HTTPException(status_code=403, detail="forbidden")
    return user


# ---- 스키마 ----

class Credentials(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class OrderIn(BaseModel):
    item: str = Field(min_length=1, max_length=128)
    qty: int = Field(default=1, ge=1, le=999)


# ---- 상태 ----

@app.get("/health")
def health():
    return {"service": "panoptes-shop", "status": "ok"}


# ---- 회원 ----

@app.post("/auth/signup", status_code=201)
def signup(body: Credentials, request: Request, db: OrmSession = Depends(get_db)):
    exists = db.scalar(select(User).where(User.username == body.username))
    if exists:
        raise HTTPException(status_code=409, detail="username taken")
    user = User(username=body.username, password_hash=security.hash_password(body.password))
    db.add(user)
    db.commit()
    set_event(request, "auth.signup", username=body.username)
    return {"id": user.id, "username": user.username}


@app.post("/auth/login")
def login(body: Credentials, request: Request, response: Response, db: OrmSession = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None:
        set_event(request, "auth.login.failure", reason="unknown_user", username=body.username)
        raise HTTPException(status_code=401, detail="invalid credentials")

    if security.is_locked(user.locked_until):
        set_event(request, "auth.login.failure", reason="locked", user=user.username)
        raise HTTPException(status_code=423, detail="account locked")

    if not security.verify_password(user.password_hash, body.password):
        user.failed_logins += 1
        if user.failed_logins >= settings.LOCKOUT_THRESHOLD:
            user.locked_until = security.lock_until()
            user.failed_logins = 0
            db.commit()
            set_event(request, "auth.lockout", user=user.username, minutes=settings.LOCKOUT_MINUTES)
            raise HTTPException(status_code=423, detail="account locked")
        db.commit()
        set_event(request, "auth.login.failure", reason="bad_password", user=user.username,
                  attempts=user.failed_logins)
        raise HTTPException(status_code=401, detail="invalid credentials")

    # 성공
    user.failed_logins = 0
    user.locked_until = None
    sess = Session(token=security.new_session_token(), user_id=user.id,
                   expires_at=security.session_expiry())
    db.add(sess)
    db.commit()
    request.state.user_id = user.id
    response.set_cookie(settings.SESSION_COOKIE, sess.token, httponly=True,
                        samesite="lax", max_age=12 * 3600)
    set_event(request, "auth.login.success", user=user.username)
    return {"status": "ok", "username": user.username, "role": user.role}


@app.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(current_user),
           db: OrmSession = Depends(get_db)):
    token = request.cookies.get(settings.SESSION_COOKIE)
    if token:
        sess = db.get(Session, token)
        if sess:
            db.delete(sess)
            db.commit()
    response.delete_cookie(settings.SESSION_COOKIE)
    return {"status": "ok"}


@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id": user.id, "username": user.username, "role": user.role}


# ---- 주문 ----

@app.get("/orders")
def list_orders(user: User = Depends(current_user), db: OrmSession = Depends(get_db)):
    rows = db.scalars(select(Order).where(Order.user_id == user.id)).all()
    return [{"id": o.id, "item": o.item, "qty": o.qty} for o in rows]


@app.get("/orders/{order_id}")
def get_order(order_id: int, request: Request, user: User = Depends(current_user),
              db: OrmSession = Depends(get_db)):
    order = db.get(Order, order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="not found")
    if order.user_id != user.id:
        # 소유자 불일치: 존재를 숨기려 404로 응답하되 보안 이벤트는 남긴다.
        set_event(request, "authz.denied", reason="owner", user=user.username, order_id=order_id,
                  owner_id=order.user_id)
        raise HTTPException(status_code=404, detail="not found")
    return {"id": order.id, "item": order.item, "qty": order.qty}


@app.post("/orders", status_code=201)
def create_order(body: OrderIn, user: User = Depends(current_user),
                 db: OrmSession = Depends(get_db)):
    order = Order(user_id=user.id, item=body.item, qty=body.qty)
    db.add(order)
    db.commit()
    return {"id": order.id, "item": order.item, "qty": order.qty}


# ---- 관리자 ----

@app.get("/admin/users")
def admin_users(user: User = Depends(require_admin), db: OrmSession = Depends(get_db)):
    rows = db.scalars(select(User)).all()
    return [{"id": u.id, "username": u.username, "role": u.role} for u in rows]


# ---- 파트너 API (API 키 인증) ----

@app.get("/partner/products")
def partner_products(request: Request, x_api_key: str | None = Header(default=None),
                     db: OrmSession = Depends(get_db)):
    if not x_api_key:
        set_event(request, "apikey.invalid", reason="missing")
        raise HTTPException(status_code=401, detail="api key required")
    digest = security.hash_api_key(x_api_key)
    key = db.scalar(select(ApiKey).where(ApiKey.key_hash == digest))
    if key is None:
        set_event(request, "apikey.invalid", reason="unknown")
        raise HTTPException(status_code=401, detail="invalid api key")
    rows = db.scalars(select(Product)).all()
    return [{"id": p.id, "name": p.name, "price": p.price} for p in rows]


# ---- 파일 업로드 ----

@app.post("/me/avatar")
async def upload_avatar(request: Request, file: UploadFile = File(...),
                        user: User = Depends(current_user)):
    if file.content_type not in settings.AVATAR_TYPES:
        set_event(request, "upload.rejected", reason="type", content_type=file.content_type)
        raise HTTPException(status_code=415, detail="unsupported media type")
    data = await file.read(settings.AVATAR_MAX_BYTES + 1)
    if len(data) > settings.AVATAR_MAX_BYTES:
        set_event(request, "upload.rejected", reason="size", limit=settings.AVATAR_MAX_BYTES)
        raise HTTPException(status_code=413, detail="file too large")
    # MVP: 저장은 하지 않고 수락만 한다(탐지 트래픽 목적).
    return {"status": "accepted", "bytes": len(data), "content_type": file.content_type}


# ---- 최소 HTML 화면 (WAF 오탐 분석용 폼 트래픽) ----

@app.get("/", response_class=HTMLResponse)
def index():
    return """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>panoptes-shop</title></head><body>
<h1>panoptes-shop</h1>
<form method="post" action="/auth/login" onsubmit="return false">
  <input name="username" placeholder="username">
  <input name="password" type="password" placeholder="password">
  <button>login</button>
</form>
<p>API: /health, /auth/*, /orders, /partner/products</p>
</body></html>"""


@app.exception_handler(HTTPException)
async def http_exc(request: Request, exc: HTTPException):
    # 라우트 의존성(current_user 등)에서 올라온 상태 코드를 로그와 함께 반환
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
