import os
from datetime import timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _parse_cors_origins():
    raw = os.getenv("VGUARD_CORS_ORIGINS", "").strip()
    defaults = [
        "http://127.0.0.1:5000",
        "http://localhost:5000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    if raw:
        origins = [o.strip() for o in raw.replace(";", ",").split(",") if o.strip()]
        return origins or defaults
    return defaults


class Config:
    """Base configuration."""

    SECRET_KEY = os.getenv("VGUARD_SECRET_KEY", "vguard-dev-secret-change-this")

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'vguard.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}

    # Session
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    SESSION_COOKIE_SECURE = os.getenv("VGUARD_COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.getenv("VGUARD_SESSION_MINUTES", "30"))
    )

    # CORS
    CORS_ORIGINS = _parse_cors_origins()

    # CSRF
    DASHBOARD_CSRF_ENABLED = os.getenv("VGUARD_DASHBOARD_CSRF", "1") == "1"
    DASHBOARD_CSRF_HEADER = "X-vGuard-CSRF"

    # Debug
    DEBUG = os.getenv("VGUARD_DEBUG", "0") == "1"

    # Environment
    ENV_MODE = os.getenv("VGUARD_ENV", "development").strip().lower()
    IS_PRODUCTION = ENV_MODE in {"prod", "production"}

    # File paths (legacy compatibility)
    LOG_FILE = os.path.join(BASE_DIR, "vguard_logs.json")
    HEARTBEAT_FILE = os.path.join(BASE_DIR, "vguard_heartbeat.txt")
    PROFILE_UPLOAD_DIR = os.path.join(BASE_DIR, "uploads", "profile_images")

    # Lab
    ENABLE_LAB_RUN = os.getenv("VGUARD_ENABLE_LAB_RUN", "0") == "1"
    LAB_PYTHON = os.getenv("VGUARD_LAB_PYTHON", "python3")
    MININET_RUN_TIMEOUT = int(os.getenv("VGUARD_MININET_RUN_TIMEOUT", "180"))

    # CSV export limits
    CSV_MAX_MB = int(os.getenv("VGUARD_CSV_MAX_MB", "100"))

    # Gemini AI
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    # Security flags
    EXPOSE_RESET_CODE_IN_API = os.getenv("VGUARD_DEV_SHOW_RESET_CODE", "0") == "1"


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    DEBUG = False
    EXPOSE_RESET_CODE_IN_API = False

    @classmethod
    def init_app(cls, app):
        if app.config["SECRET_KEY"] == "vguard-dev-secret-change-this":
            raise RuntimeError(
                "VGUARD_SECRET_KEY must be set in production. "
                'Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"'
            )


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    DASHBOARD_CSRF_ENABLED = False
    EXPOSE_RESET_CODE_IN_API = True


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}
