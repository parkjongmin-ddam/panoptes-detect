"""초기 시드 데이터. 멱등하게 동작한다(중복 생성 안 함).

테스트·탐지 시나리오용 계정과 데이터. 비밀번호는 lab 전용이며 운영 금지.
API 키 원문은 로그·응답에 남기지 않고, seed 시 1회 stdout에만 안내한다.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

import security
from db import ApiKey, Order, Product, User

# lab 전용 고정값 (운영 사용 금지)
SEED_USERS = [
    ("admin", "admin-lab-pw", "admin"),
    ("alice", "alice-lab-pw", "user"),
    ("bob", "bob-lab-pw", "user"),
]
SEED_API_KEY = "panoptes-partner-lab-key"
SEED_PRODUCTS = [("keyboard", 39000), ("mouse", 19000), ("monitor", 210000)]


def seed(db: OrmSession) -> None:
    if db.scalar(select(User).limit(1)) is not None:
        return  # 이미 시드됨

    users = {}
    for name, pw, role in SEED_USERS:
        u = User(username=name, password_hash=security.hash_password(pw), role=role)
        db.add(u)
        users[name] = u
    db.flush()

    db.add(Order(user_id=users["alice"].id, item="keyboard", qty=1))
    db.add(Order(user_id=users["alice"].id, item="mouse", qty=2))
    db.add(Order(user_id=users["bob"].id, item="monitor", qty=1))

    db.add(ApiKey(name="partner-lab", key_hash=security.hash_api_key(SEED_API_KEY)))

    for pname, price in SEED_PRODUCTS:
        db.add(Product(name=pname, price=price))

    db.commit()
    print(f'{{"logger":"panoptes.seed","event":"seeded","users":{len(SEED_USERS)},'
          f'"note":"lab credentials in app/seed.py"}}', flush=True)
