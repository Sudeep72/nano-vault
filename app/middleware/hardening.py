"""Security Hardening additions — NanoVault v3.0 Final Completion."""
from __future__ import annotations
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

_FAILED_LOGIN_TRACKER: dict[str, list[float]] = {}
BRUTE_FORCE_WINDOW_SECONDS = 300
BRUTE_FORCE_MAX_ATTEMPTS = 5


def record_failed_login(identifier: str) -> None:
    now = time.time()
    attempts = _FAILED_LOGIN_TRACKER.setdefault(identifier, [])
    attempts.append(now)
    _FAILED_LOGIN_TRACKER[identifier] = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW_SECONDS]


def is_locked_out(identifier: str) -> bool:
    attempts = _FAILED_LOGIN_TRACKER.get(identifier, [])
    now = time.time()
    recent = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW_SECONDS]
    return len(recent) >= BRUTE_FORCE_MAX_ATTEMPTS


def clear_failed_logins(identifier: str) -> None:
    _FAILED_LOGIN_TRACKER.pop(identifier, None)


def get_lockout_status(identifier: str) -> dict:
    attempts = _FAILED_LOGIN_TRACKER.get(identifier, [])
    now = time.time()
    recent = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW_SECONDS]
    return {
        "locked": len(recent) >= BRUTE_FORCE_MAX_ATTEMPTS,
        "attempts": len(recent),
        "max_attempts": BRUTE_FORCE_MAX_ATTEMPTS,
        "window_seconds": BRUTE_FORCE_WINDOW_SECONDS,
    }


class CSRFService:
    """Double-submit-cookie CSRF protection for dashboard/browser-based clients.
    API clients using Bearer tokens are exempt (no ambient credential to forge)."""

    def __init__(self, secret: str):
        self._secret = secret.encode()

    def generate_token(self, session_id: str) -> str:
        sig = hmac.new(self._secret, session_id.encode(), hashlib.sha256).hexdigest()
        return f"{session_id}.{sig}"

    def validate_token(self, token: str) -> bool:
        try:
            session_id, sig = token.rsplit(".", 1)
            expected = hmac.new(self._secret, session_id.encode(), hashlib.sha256).hexdigest()
            return hmac.compare_digest(sig, expected)
        except Exception:
            return False


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforces CSRF token on state-changing requests that carry a session cookie
    (i.e. dashboard/browser flows). Bearer-token API calls are unaffected."""

    def __init__(self, app, csrf_service: CSRFService):
        super().__init__(app)
        self.csrf_service = csrf_service

    async def dispatch(self, request: Request, call_next) -> Response:
        uses_cookie_session = "nv_session" in request.cookies
        state_changing = request.method in ("POST", "PUT", "PATCH", "DELETE")

        if uses_cookie_session and state_changing:
            csrf_header = request.headers.get("X-CSRF-Token", "")
            if not self.csrf_service.validate_token(csrf_header):
                return JSONResponse(status_code=403, content={"success": False, "error": "CSRF token missing or invalid"})

        return await call_next(request)


class SessionIdleTimeoutMiddleware(BaseHTTPMiddleware):
    """Tracks last-activity timestamp per session cookie; expires idle sessions."""

    def __init__(self, app, idle_timeout_seconds: int = 1800):
        super().__init__(app)
        self.idle_timeout = idle_timeout_seconds
        self._last_activity: dict[str, float] = {}

    async def dispatch(self, request: Request, call_next) -> Response:
        session_id = request.cookies.get("nv_session")
        if session_id:
            now = time.time()
            last = self._last_activity.get(session_id)
            if last and (now - last) > self.idle_timeout:
                response = JSONResponse(status_code=401, content={"success": False, "error": "Session expired due to inactivity"})
                response.delete_cookie("nv_session")
                return response
            self._last_activity[session_id] = now

        response = await call_next(request)
        if session_id:
            response.set_cookie(
                "nv_session", session_id,
                httponly=True, secure=True, samesite="strict",
                max_age=self.idle_timeout,
            )
        return response


def secure_redaction(text: str, patterns: list[str] = None) -> str:
    """Redact common secret-shaped substrings from log lines before they're written."""
    import re
    patterns = patterns or [
        r'(?i)(password["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)',
        r'(?i)(api[_-]?key["\']?\s*[:=]\s*["\']?)([^"\'\s,}]+)',
        r'(?i)(token["\']?\s*[:=]\s*["\']?)([A-Za-z0-9\-_.]{10,})',
        r'(vault:v\d+:)([A-Za-z0-9+/=]{10,})',  # transit ciphertext/signature tokens
    ]
    redacted = text
    for p in patterns:
        redacted = re.sub(p, r"\1***REDACTED***", redacted)
    return redacted
