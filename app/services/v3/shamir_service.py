from __future__ import annotations
import base64, hashlib, secrets
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException
from app.models.models import VaultSealState, ShamirShare, SealStatus
from app.core.encryption import encryption_service

def _now(): return datetime.now(timezone.utc)
def _hash_share(s): return hashlib.sha256(s.encode()).hexdigest()
def _xor(a, b): return bytes(x ^ y for x, y in zip(a, b))

class ShamirService:
    @staticmethod
    def _split(secret_bytes, total, threshold):
        if threshold < 2 or threshold > total: raise ValueError("Invalid threshold")
        shares = [secrets.token_bytes(len(secret_bytes)) for _ in range(total - 1)]
        last = secret_bytes
        for s in shares: last = _xor(last, s)
        shares.append(last)
        return [f"{i+1}:{base64.b64encode(s).decode()}" for i, s in enumerate(shares)]

    @staticmethod
    async def initialize(db: AsyncSession, total_shares=5, threshold=3):
        existing = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        if existing and existing.initialized: raise HTTPException(400, "Vault already initialized")
        master = secrets.token_bytes(32)
        shares = ShamirService._split(master, total_shares, threshold)
        enc_master = encryption_service.encrypt(base64.b64encode(master).decode())
        if existing:
            existing.status = SealStatus.SEALED; existing.total_shares = total_shares
            existing.threshold = threshold; existing.shares_provided = 0
            existing.encrypted_master_key = enc_master; existing.initialized = True
            existing.sealed_at = _now(); existing.unsealed_at = None
        else:
            db.add(VaultSealState(status=SealStatus.SEALED, total_shares=total_shares, threshold=threshold,
                shares_provided=0, encrypted_master_key=enc_master, initialized=True, sealed_at=_now()))
        for i, share in enumerate(shares):
            db.add(ShamirShare(share_index=i+1, share_hash=_hash_share(share), distributed_to=f"key-holder-{i+1}"))
        await db.flush()
        return {"initialized": True, "total_shares": total_shares, "threshold": threshold, "shares": shares,
                "warning": "Store these shares securely. Shown once, never stored."}

    @staticmethod
    async def unseal(db: AsyncSession, share: str):
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        if not state: raise HTTPException(400, "Vault not initialized")
        if state.status == SealStatus.UNSEALED:
            return {"sealed": False, "progress": state.total_shares, "threshold": state.threshold, "message": "Already unsealed"}
        sh = (await db.execute(select(ShamirShare).where(ShamirShare.share_hash==_hash_share(share)))).scalar_one_or_none()
        if not sh: raise HTTPException(400, "Invalid key share")
        if sh.used_at: raise HTTPException(400, "Share already used")
        sh.used_at = _now(); state.shares_provided += 1; await db.flush()
        if state.shares_provided >= state.threshold:
            state.status = SealStatus.UNSEALED; state.unsealed_at = _now()
            for s in (await db.execute(select(ShamirShare))).scalars().all(): s.used_at = None
            state.shares_provided = 0; await db.flush()
            return {"sealed": False, "progress": state.threshold, "threshold": state.threshold, "message": "Vault unsealed"}
        return {"sealed": True, "progress": state.shares_provided, "threshold": state.threshold,
                "message": f"{state.threshold - state.shares_provided} more share(s) needed"}

    @staticmethod
    async def seal(db: AsyncSession):
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        if not state: raise HTTPException(400, "Vault not initialized")
        state.status = SealStatus.SEALED; state.sealed_at = _now(); state.unsealed_at = None; state.shares_provided = 0
        for s in (await db.execute(select(ShamirShare))).scalars().all(): s.used_at = None
        await db.flush(); return {"sealed": True, "sealed_at": state.sealed_at.isoformat()}
    @staticmethod
    async def require_unsealed(db: AsyncSession):
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()

        if not state:
            raise HTTPException(status_code=400, detail="Vault not initialized")

        if state.status == SealStatus.SEALED:
            raise HTTPException(status_code=503, detail="Vault is sealed")

    @staticmethod
    async def get_status(db: AsyncSession):
        state = (await db.execute(select(VaultSealState))).scalar_one_or_none()
        if not state: return {"initialized": False, "sealed": True, "progress": 0, "threshold": 0, "total_shares": 0}
        return {"initialized": state.initialized, "sealed": state.status == SealStatus.SEALED,
                "progress": state.shares_provided, "threshold": state.threshold, "total_shares": state.total_shares,
                "unsealed_at": state.unsealed_at.isoformat() if state.unsealed_at else None,
                "sealed_at": state.sealed_at.isoformat() if state.sealed_at else None,
                "unseal_provider": state.unseal_provider}

shamir_service = ShamirService()
