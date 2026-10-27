"""구조화 JSON 로깅 미들웨어 (spec 4절).

요청마다 한 줄 JSON을 stdout에 출력한다. WAF가 넘긴 X-Request-ID와
X-Forwarded-For를 이어받아 WAF 이벤트와 앱 이벤트를 연결할 수 있게 한다.
비밀번호·세션값·API 키 원문은 절대 남기지 않는다.
"""
from __future__ import annotations

import datetime as dt
import json
import secrets
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from config import settings


def set_event(request: Request, event: str, **fields) -> None:
    """핸들러가 호출: 이번 요청 로그에 보안 이벤트 코드와 부가 필드를 싣는다.

    BaseHTTPMiddleware는 엔드포인트를 별도 컨텍스트에서 실행하므로 ContextVar는
    미들웨어로 전파되지 않는다. 동일 Request 객체에 공유되는 request.state를 쓴다.
    """
    request.state.sec_event = {"event": event, **fields}


def client_ip(request: Request) -> str:
    if settings.TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "-"


def _emit(record: dict) -> None:
    print(json.dumps(record, ensure_ascii=False, separators=(",", ":")), flush=True)


class AccessLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.sec_event = None
        rid = request.headers.get("x-request-id") or secrets.token_hex(8)
        request.state.request_id = rid
        request.state.client_ip = client_ip(request)
        start = time.perf_counter()

        response = await call_next(request)

        latency_ms = round((time.perf_counter() - start) * 1000, 1)
        record = {
            "ts": dt.datetime.now(dt.timezone.utc).isoformat(),
            "logger": "panoptes.app",
            "request_id": rid,
            "client_ip": request.state.client_ip,
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "latency_ms": latency_ms,
        }
        uid = getattr(request.state, "user_id", None)
        if uid is not None:
            record["user_id"] = uid
        ev = getattr(request.state, "sec_event", None)
        if ev:
            record.update(ev)
        _emit(record)
        response.headers["X-Request-ID"] = rid
        return response
