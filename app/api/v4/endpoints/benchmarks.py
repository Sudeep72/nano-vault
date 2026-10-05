"""Cryptography Performance Lab + Enterprise Benchmark Suite — NanoVault v4.0"""
from __future__ import annotations
import time
import uuid
from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.core.dependencies import get_current_user, require_admin
from app.core.responses import ok, created

router = APIRouter(prefix="/benchmarks", tags=["Benchmarking"])


@router.post("/crypto/run", summary="Run full Cryptography Performance Lab (AES/ChaCha20/RSA/Ed25519/ECDSA) [Admin]")
async def run_crypto_benchmark(db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    result = crypto_benchmark_service.run_crypto_suite()
    run = await crypto_benchmark_service.save_run(db, "crypto", result["results"], result["duration_ms"], admin.id)
    return created({"run_id": str(run.id), **result}, "Crypto benchmark complete")


@router.post("/crypto/aes", summary="Benchmark AES-256-GCM only")
async def bench_aes(n: int = 200, _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(crypto_benchmark_service.benchmark_aes_gcm(n), "AES-256-GCM benchmark")


@router.post("/crypto/chacha20", summary="Benchmark ChaCha20-Poly1305 only")
async def bench_chacha(n: int = 200, _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(crypto_benchmark_service.benchmark_chacha20(n), "ChaCha20-Poly1305 benchmark")


@router.post("/crypto/rsa", summary="Benchmark RSA-4096 only (slow — small n by default)")
async def bench_rsa(n: int = 3, _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(crypto_benchmark_service.benchmark_rsa4096(n), "RSA-4096 benchmark")


@router.post("/crypto/ed25519", summary="Benchmark Ed25519 only")
async def bench_ed25519(n: int = 200, _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(crypto_benchmark_service.benchmark_ed25519(n), "Ed25519 benchmark")


@router.post("/crypto/ecdsa", summary="Benchmark ECDSA-P256 only")
async def bench_ecdsa(n: int = 100, _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(crypto_benchmark_service.benchmark_ecdsa(n), "ECDSA-P256 benchmark")


@router.post("/subsystem/run", summary="Run Enterprise Benchmark Suite across all subsystems [Admin]")
async def run_subsystem_benchmark(db: AsyncSession = Depends(get_db), admin=Depends(require_admin)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    t0 = time.perf_counter()
    result = await crypto_benchmark_service.run_subsystem_benchmark(db)
    duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    run = await crypto_benchmark_service.save_run(db, "subsystem", result["subsystem_results"], duration_ms, admin.id)
    return created({"run_id": str(run.id), "duration_ms": duration_ms, **result}, "Subsystem benchmark complete")


@router.get("/history", summary="Benchmark run history")
async def benchmark_history(benchmark_type: Optional[str] = None, limit: int = 20,
                            db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(await crypto_benchmark_service.get_history(db, benchmark_type, limit), "Benchmark history")


@router.get("/compare", summary="Compare two benchmark runs")
async def compare_runs(run_a: uuid.UUID, run_b: uuid.UUID, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    from app.services.v4.crypto_benchmark_service import crypto_benchmark_service
    return ok(await crypto_benchmark_service.compare_runs(db, run_a, run_b), "Benchmark comparison")
