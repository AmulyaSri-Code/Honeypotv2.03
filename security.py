"""Authentication and token helpers for Honeypot v3.00."""

import hashlib
import hmac
import os
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

DEFAULT_AUTH_SECRET = "change-me-in-production"
MIN_AUTH_SECRET_LENGTH = 32
MIN_ADMIN_PASSWORD_LENGTH = 12
BAD_ADMIN_PASSWORDS = {
    "", "secret", "password", "admin", "admin123", "change_this_now",
    "replace_with_a_strong_password", "changeme", "change-me", "default",
}


def _auth_secret() -> str:
    return os.environ.get("HONEYPOT_AUTH_SECRET", DEFAULT_AUTH_SECRET)


def is_development_mode() -> bool:
    mode = os.environ.get("HONEYPOT_ENV") or os.environ.get("FLASK_ENV") or ""
    return mode.strip().lower() in {"dev", "development", "local", "test", "testing"}


def auth_secret_is_strong(secret: str | None) -> bool:
    value = (secret or "").strip()
    return value != DEFAULT_AUTH_SECRET and len(value) >= MIN_AUTH_SECRET_LENGTH


def admin_password_is_strong(password: str | None) -> bool:
    value = password or ""
    return value.strip().lower() not in BAD_ADMIN_PASSWORDS and len(value) >= MIN_ADMIN_PASSWORD_LENGTH


def bootstrap_token_is_strong(token: str | None) -> bool:
    return len((token or "").strip()) >= 32


def hash_password(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000,
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = stored_hash.split("$", 1)
    except ValueError:
        return False
    candidate = hash_password(password, salt)
    return hmac.compare_digest(candidate, f"{salt}${digest}")


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_auth_secret(), salt="honeypot-auth")


def create_token(payload: dict) -> str:
    return _serializer().dumps(payload)


def verify_token(token: str, max_age_seconds: int = 8 * 3600) -> dict | None:
    try:
        return _serializer().loads(token, max_age=max_age_seconds)
    except (BadSignature, SignatureExpired):
        return None


def generate_api_key(prefix: str = "hpv3") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
