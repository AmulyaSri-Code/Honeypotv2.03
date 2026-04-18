"""Authentication and token helpers for Honeypot v3.00."""

import hashlib
import hmac
import os
import secrets
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


def _auth_secret() -> str:
    return os.environ.get("HONEYPOT_AUTH_SECRET", "change-me-in-production")


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
