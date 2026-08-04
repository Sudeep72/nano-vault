"""
Redis Performance Layer — NanoVault v3.0 Final Completion.
Optional cache with automatic fallback when Redis is unavailable.
"""
from __future__ import annotations
import json
import logging
import os
import time
from typing import Optional, Any

logger = logging.getLogger("nano_vault.cache")

_redis_client = None
_available = False
_stats = {"hits": 0, "misses": 0, "sets": 0, "invalidations": 0, "errors": 0}


def init_cache(redis_url: str = None) -> bool:
    """Try to connect to Redis. If unavailable, cache silently no-ops."""
    global _redis_client, _available
    redis_url = redis_url or os.environ.get("REDIS_URL", "")
    if not redis_url:
        logger.info("REDIS_URL not set — cache layer disabled, running without cache")
        return False
    try:
        import redis
        _redis_client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
        _redis_client.ping()
        _available = True
        logger.info("Redis cache connected: %s", redis_url)
        return True
    except Exception as e:
        logger.warning("Redis unavailable, falling back to no-cache mode: %s", e)
        _redis_client = None
        _available = False
        return False


CACHE_NAMESPACES = [
    "secret_metadata", "transit_key", "pki_metadata",
    "policy", "identity", "namespace", "engine_registry",
]


def _key(namespace: str, key: str) -> str:
    return f"nanovault:{namespace}:{key}"


def cache_get(namespace: str, key: str) -> Optional[Any]:
    if not _available:
        return None
    try:
        raw = _redis_client.get(_key(namespace, key))
        if raw is None:
            _stats["misses"] += 1
            return None
        _stats["hits"] += 1
        return json.loads(raw)
    except Exception as e:
        _stats["errors"] += 1
        logger.warning("Cache get failed: %s", e)
        return None


def cache_set(namespace: str, key: str, value: Any, ttl_seconds: int = 300) -> bool:
    if not _available:
        return False
    try:
        _redis_client.setex(_key(namespace, key), ttl_seconds, json.dumps(value, default=str))
        _stats["sets"] += 1
        return True
    except Exception as e:
        _stats["errors"] += 1
        logger.warning("Cache set failed: %s", e)
        return False


def cache_invalidate(namespace: str, key: str = None) -> int:
    """Invalidate a specific key, or all keys in a namespace if key is None."""
    if not _available:
        return 0
    try:
        if key:
            deleted = _redis_client.delete(_key(namespace, key))
        else:
            pattern = _key(namespace, "*")
            keys = list(_redis_client.scan_iter(match=pattern))
            deleted = _redis_client.delete(*keys) if keys else 0
        _stats["invalidations"] += 1
        return deleted
    except Exception as e:
        _stats["errors"] += 1
        return 0


def cache_warm(namespace: str, items: dict[str, Any], ttl_seconds: int = 300) -> int:
    """Bulk-populate cache — used at startup for hot data (policies, engine registry)."""
    if not _available:
        return 0
    count = 0
    for k, v in items.items():
        if cache_set(namespace, k, v, ttl_seconds):
            count += 1
    return count


def health() -> dict:
    if not _available:
        return {"available": False, "message": "Redis not configured or unreachable — running in no-cache fallback mode"}
    try:
        _redis_client.ping()
        return {"available": True, "message": "Redis healthy"}
    except Exception as e:
        return {"available": False, "message": str(e)}


def get_stats() -> dict:
    total = _stats["hits"] + _stats["misses"]
    hit_rate = round(_stats["hits"] / total, 3) if total else 0.0
    return {**_stats, "hit_rate": hit_rate, "available": _available, "namespaces": CACHE_NAMESPACES}
