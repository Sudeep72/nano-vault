"""
Interactive API Playground — NanoVault v4.0

Executes a real request against this same running application (in-process,
via httpx.ASGITransport — no network hop, no separate process) and returns
the actual response, actual status code, and actual execution time. This
is a genuine "try it" executor, not a canned response.
"""
from __future__ import annotations
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

_now = lambda: datetime.now(timezone.utc)


class PlaygroundService:

    @staticmethod
    async def execute(app, method: str, path: str, token: Optional[str] = None,
                      namespace: Optional[str] = None, json_body: Optional[dict] = None) -> dict:
        """
        Real in-process HTTP execution against the live FastAPI app instance.
        Uses httpx's ASGITransport so no actual socket/network is involved —
        this is the same mechanism the test suite uses (tests/conftest.py),
        applied here as a live playground rather than a test harness.
        """
        import httpx

        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if namespace:
            headers["X-Vault-Namespace"] = namespace

        t0 = time.perf_counter()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://playground") as client:
            resp = await client.request(method.upper(), path, headers=headers, json=json_body)
        execution_ms = round((time.perf_counter() - t0) * 1000, 2)

        try:
            response_body = resp.json()
        except Exception:
            response_body = resp.text

        return {
            "request": {"method": method.upper(), "path": path, "namespace": namespace,
                       "had_token": bool(token), "body": json_body},
            "response": {"status_code": resp.status_code, "body": response_body},
            "execution_time_ms": execution_ms,
            "executed_at": _now().isoformat(),
        }

    @staticmethod
    def get_example_payloads() -> dict:
        """Curated example payloads for common playground actions — real shapes
        matching the actual Pydantic schemas in app/schemas/schemas.py."""
        return {
            "POST /api/v1/auth/login": {"username": "demo_user", "password": "DemoPass123!"},
            "POST /api/v1/secrets": {"key": "example/key", "value": "example-value", "category": "demo", "tags": ["example"]},
            "POST /api/v3/transit/keys": {"name": "example-key", "key_type": "aes-256-gcm", "exportable": False},
            "POST /api/v3/transit/encrypt/example-key": {"plaintext": "ZXhhbXBsZQ=="},
            "POST /api/v3/pki/ca/root": {"name": "example-ca", "subject_dn": "CN=example-ca,O=Demo,C=US", "ttl_days": 3650, "key_size": 2048},
        }


playground_service = PlaygroundService()
