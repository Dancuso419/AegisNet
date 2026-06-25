import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "change-me"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///aegisnet.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
    GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")

    # Session cookie hardening
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Send cookies only over HTTPS in production (set FLASK_DEBUG=0).
    SESSION_COOKIE_SECURE = os.environ.get("FLASK_DEBUG", "0").lower() not in ("1", "true", "yes", "on")
