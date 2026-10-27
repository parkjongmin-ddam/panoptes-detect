"""테스트 픽스처. 앱 임포트 전에 SQLite 임시 DB로 환경을 세팅한다."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# app 소스를 import 경로에 추가
APP_DIR = Path(__file__).resolve().parent.parent / "app"
sys.path.insert(0, str(APP_DIR))

# 엔진 생성(= db.py import) 전에 반드시 설정
_tmp = tempfile.mkdtemp(prefix="panoptes-test-")
os.environ["DATABASE_URL"] = f"sqlite+pysqlite:///{_tmp}/test.db"
os.environ["SESSION_SECRET"] = "test-secret"
os.environ["LOCKOUT_THRESHOLD"] = "3"
os.environ["LOCKOUT_MINUTES"] = "10"
os.environ["TRUST_PROXY"] = "true"


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    import main  # noqa: E402  (env 설정 후 import)

    with TestClient(main.app) as c:
        yield c
