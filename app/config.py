"""환경변수 기반 설정 (spec 5절)."""
import os


class Settings:
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "postgresql+psycopg://panoptes:panoptes@db:5432/panoptes"
    )
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "dev-only-change-me")
    SESSION_COOKIE: str = os.getenv("SESSION_COOKIE", "panoptes_session")
    LOCKOUT_THRESHOLD: int = int(os.getenv("LOCKOUT_THRESHOLD", "5"))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", "10"))
    # X-Forwarded-For를 신뢰할지 여부. WAF 뒤에 있을 때만 true.
    TRUST_PROXY: bool = os.getenv("TRUST_PROXY", "true").lower() == "true"
    # 업로드 제한
    AVATAR_MAX_BYTES: int = int(os.getenv("AVATAR_MAX_BYTES", str(512 * 1024)))
    AVATAR_TYPES: tuple = ("image/png", "image/jpeg", "image/webp")


settings = Settings()
