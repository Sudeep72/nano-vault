"""
Cryptography Performance Lab + Enterprise Benchmark Suite — NanoVault v4.0

Real timing measurements of actual cryptographic primitives already used
elsewhere in this codebase (app/engines/transit/engine.py, app/core/encryption.py).
No simulated numbers — every figure is a real perf_counter measurement.
"""
from __future__ import annotations
import os
import time
import tracemalloc
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import BenchmarkRun, BenchmarkStatus

_now = lambda: datetime.now(timezone.utc)


def _time_ops(fn, n: int) -> dict:
    t0 = time.perf_counter()
    for _ in range(n):
        fn()
    elapsed = time.perf_counter() - t0
    return {
        "total_ms": round(elapsed * 1000, 3),
        "ops": n,
        "avg_us_per_op": round((elapsed / n) * 1_000_000, 2),
        "throughput_ops_per_sec": round(n / elapsed, 1) if elapsed > 0 else None,
    }


class CryptoBenchmarkService:

    @staticmethod
    def benchmark_aes_gcm(n: int = 200) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = AESGCM.generate_key(bit_length=256)
        aesgcm = AESGCM(key)
        payload = os.urandom(1024)
        nonce = os.urandom(12)

        enc = _time_ops(lambda: aesgcm.encrypt(os.urandom(12), payload, None), n)
        ct = aesgcm.encrypt(nonce, payload, None)
        dec = _time_ops(lambda: aesgcm.decrypt(nonce, ct, None), n)
        keygen = _time_ops(lambda: AESGCM.generate_key(bit_length=256), n)
        return {"algorithm": "AES-256-GCM", "encrypt": enc, "decrypt": dec, "key_generation": keygen}

    @staticmethod
    def benchmark_chacha20(n: int = 200) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = ChaCha20Poly1305.generate_key()
        cipher = ChaCha20Poly1305(key)
        payload = os.urandom(1024)
        nonce = os.urandom(12)

        enc = _time_ops(lambda: cipher.encrypt(os.urandom(12), payload, None), n)
        ct = cipher.encrypt(nonce, payload, None)
        dec = _time_ops(lambda: cipher.decrypt(nonce, ct, None), n)
        return {"algorithm": "ChaCha20-Poly1305", "encrypt": enc, "decrypt": dec}

    @staticmethod
    def benchmark_rsa4096(n: int = 3) -> dict:
        """RSA is expensive — default n is intentionally small."""
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes

        keygen_t0 = time.perf_counter()
        priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        keygen_ms = round((time.perf_counter() - keygen_t0) * 1000, 2)
        pub = priv.public_key()
        payload = os.urandom(32)  # RSA can only sign/encrypt small payloads

        sign = _time_ops(lambda: priv.sign(payload, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256()), n)
        sig = priv.sign(payload, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
        verify = _time_ops(lambda: pub.verify(sig, payload, padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256()), n)
        return {"algorithm": "RSA-4096", "key_generation_ms": keygen_ms, "sign": sign, "verify": verify,
                "note": f"n={n} ops due to RSA-4096 cost — not comparable 1:1 with symmetric algorithm counts"}

    @staticmethod
    def benchmark_ed25519(n: int = 200) -> dict:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        payload = os.urandom(256)

        keygen = _time_ops(lambda: Ed25519PrivateKey.generate(), n)
        sign = _time_ops(lambda: priv.sign(payload), n)
        sig = priv.sign(payload)
        verify = _time_ops(lambda: pub.verify(sig, payload), n)
        return {"algorithm": "Ed25519", "key_generation": keygen, "sign": sign, "verify": verify}

    @staticmethod
    def benchmark_ecdsa(n: int = 100) -> dict:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        payload = os.urandom(256)

        keygen = _time_ops(lambda: ec.generate_private_key(ec.SECP256R1()), n)
        sign = _time_ops(lambda: priv.sign(payload, ec.ECDSA(hashes.SHA256())), n)
        sig = priv.sign(payload, ec.ECDSA(hashes.SHA256()))
        verify = _time_ops(lambda: pub.verify(sig, payload, ec.ECDSA(hashes.SHA256())), n)
        return {"algorithm": "ECDSA-P256", "key_generation": keygen, "sign": sign, "verify": verify}

    @staticmethod
    def run_crypto_suite() -> dict:
        """Full crypto lab run — all 5 algorithms, with real memory tracking."""
        tracemalloc.start()
        t0 = time.perf_counter()

        results = {
            "aes_256_gcm": CryptoBenchmarkService.benchmark_aes_gcm(),
            "chacha20_poly1305": CryptoBenchmarkService.benchmark_chacha20(),
            "rsa_4096": CryptoBenchmarkService.benchmark_rsa4096(),
            "ed25519": CryptoBenchmarkService.benchmark_ed25519(),
            "ecdsa_p256": CryptoBenchmarkService.benchmark_ecdsa(),
        }

        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        return {
            "results": results,
            "duration_ms": duration_ms,
            "memory_current_kb": round(current / 1024, 1),
            "memory_peak_kb": round(peak / 1024, 1),
            "ran_at": _now().isoformat(),
        }

    @staticmethod
    async def run_subsystem_benchmark(db: AsyncSession) -> dict:
        """Enterprise Benchmark Suite — times real DB roundtrips per subsystem."""
        from sqlalchemy import select, func, text
        from app.models.models import Secret, TransitKey, Certificate, User, Policy, Lease, VaultToken

        async def timed_count(model):
            t0 = time.perf_counter()
            result = (await db.execute(select(func.count()).select_from(model))).scalar_one()
            return {"count": result, "query_ms": round((time.perf_counter() - t0) * 1000, 3)}

        t0 = time.perf_counter()
        await db.execute(text("SELECT 1"))
        db_roundtrip_ms = round((time.perf_counter() - t0) * 1000, 3)

        results = {
            "database_roundtrip_ms": db_roundtrip_ms,
            "auth": await timed_count(User),
            "secrets": await timed_count(Secret),
            "transit": await timed_count(TransitKey),
            "pki": await timed_count(Certificate),
            "policies": await timed_count(Policy),
            "leases": await timed_count(Lease),
            "tokens": await timed_count(VaultToken),
        }
        return {"subsystem_results": results, "ran_at": _now().isoformat()}

    @staticmethod
    async def save_run(db: AsyncSession, benchmark_type: str, results: dict,
                       duration_ms: float, created_by: Optional[uuid.UUID] = None) -> BenchmarkRun:
        run = BenchmarkRun(
            benchmark_type=benchmark_type, status=BenchmarkStatus.COMPLETED,
            results=results, duration_ms=duration_ms, created_by=created_by,
            summary=f"{benchmark_type} benchmark — {len(results)} metric group(s)",
        )
        db.add(run)
        await db.flush()
        return run

    @staticmethod
    async def get_history(db: AsyncSession, benchmark_type: Optional[str] = None, limit: int = 20) -> list[dict]:
        from sqlalchemy import select
        q = select(BenchmarkRun).order_by(BenchmarkRun.created_at.desc()).limit(limit)
        if benchmark_type:
            q = q.where(BenchmarkRun.benchmark_type == benchmark_type)
        runs = (await db.execute(q)).scalars().all()
        return [{
            "id": str(r.id), "type": r.benchmark_type, "status": r.status.value,
            "duration_ms": r.duration_ms, "created_at": r.created_at.isoformat(),
            "summary": r.summary,
        } for r in runs]

    @staticmethod
    async def compare_runs(db: AsyncSession, run_id_a: uuid.UUID, run_id_b: uuid.UUID) -> dict:
        from sqlalchemy import select
        a = (await db.execute(select(BenchmarkRun).where(BenchmarkRun.id == run_id_a))).scalar_one_or_none()
        b = (await db.execute(select(BenchmarkRun).where(BenchmarkRun.id == run_id_b))).scalar_one_or_none()
        if not a or not b:
            return {"error": "One or both benchmark runs not found"}
        delta_ms = b.duration_ms - a.duration_ms
        pct_change = round((delta_ms / a.duration_ms) * 100, 2) if a.duration_ms else None
        return {
            "run_a": {"id": str(a.id), "duration_ms": a.duration_ms, "created_at": a.created_at.isoformat()},
            "run_b": {"id": str(b.id), "duration_ms": b.duration_ms, "created_at": b.created_at.isoformat()},
            "delta_ms": round(delta_ms, 2), "pct_change": pct_change,
            "faster": "run_b" if delta_ms < 0 else ("run_a" if delta_ms > 0 else "equal"),
        }


crypto_benchmark_service = CryptoBenchmarkService()
