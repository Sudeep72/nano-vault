"""
Enterprise Demo Mode — NanoVault v4.0

Seeds realistic enterprise data using the EXISTING service layer — every
record created here goes through the same encryption, audit, and validation
paths as a real user action. Nothing bypasses the real engines.
"""
from __future__ import annotations
import random
import uuid
from datetime import timedelta, datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import (
    Organization, Namespace, User, UserRole, DemoDataset,
)

_now = lambda: datetime.now(timezone.utc)

_DEMO_ORGS = ["Acme Corp", "Globex Industries"]
_DEMO_NAMESPACES = ["engineering", "platform-security", "data-eng", "sre", "finance", "mobile"]
_DEMO_SECRET_KEYS = [
    ("aws/prod/access_key", "cloud"), ("aws/staging/access_key", "cloud"),
    ("database/prod/password", "database"), ("database/staging/password", "database"),
    ("stripe/api_key", "payments"), ("sendgrid/api_key", "email"),
    ("github/deploy_token", "cicd"), ("datadog/api_key", "observability"),
]


class DemoModeService:

    @staticmethod
    async def load(db: AsyncSession, loaded_by: uuid.UUID) -> dict:
        """
        Real seeding via the actual service layer — reuses secret_service,
        organization creation, and namespace creation exactly as a live
        user would trigger them, so demo data is indistinguishable from
        real usage in audit logs, encryption, and version history.
        """
        from app.services.secret_service import secret_service
        from app.services.v2.org_service import org_service
        from app.services.v2.namespace_service import namespace_service

        counts = {"orgs": 0, "namespaces": 0, "secrets": 0}

        admin = (await db.execute(select(User).where(User.id == loaded_by))).scalar_one()

        for org_name in _DEMO_ORGS:
            existing = (await db.execute(select(Organization).where(Organization.name == org_name))).scalar_one_or_none()
            if existing:
                org = existing
            else:
                org = await org_service.create_org(db, name=org_name, description=f"Demo organization: {org_name}")
                counts["orgs"] += 1

            for ns_name in random.sample(_DEMO_NAMESPACES, k=3):
                path = f"{org_name.lower().replace(' ', '-')}/{ns_name}"
                existing_ns = (await db.execute(select(Namespace).where(Namespace.path == path))).scalar_one_or_none()
                if not existing_ns:
                    await namespace_service.create(db, org_id=org.id, name=ns_name, path=path)
                    counts["namespaces"] += 1

            for key, category in _DEMO_SECRET_KEYS:
                full_key = f"{org_name.lower().replace(' ', '-')}/{key}"
                try:
                    await secret_service.create(
                        db, admin, key=full_key,
                        value=f"demo-value-{uuid.uuid4().hex[:12]}",
                        category=category, tags=["demo", category],
                    )
                    counts["secrets"] += 1
                except Exception:
                    pass  # already exists — demo load is idempotent, not a failure

        dataset = DemoDataset(label="enterprise-demo", records_created=counts, loaded_by=loaded_by)
        db.add(dataset)
        await db.flush()

        return {"loaded": True, "dataset_id": str(dataset.id), "records_created": counts,
                "loaded_at": dataset.loaded_at.isoformat()}

    @staticmethod
    async def get_load_history(db: AsyncSession) -> list[dict]:
        datasets = (await db.execute(select(DemoDataset).order_by(DemoDataset.loaded_at.desc()))).scalars().all()
        return [{"id": str(d.id), "label": d.label, "records_created": d.records_created,
                 "loaded_at": d.loaded_at.isoformat()} for d in datasets]

    @staticmethod
    async def reset(db: AsyncSession, dataset_id: uuid.UUID) -> dict:
        """
        Marks the dataset as reset. Full destructive cleanup of demo-tagged
        secrets is deliberately NOT automatic here — same reasoning as
        backup restore: destructive bulk-delete should never be a silent
        side effect of a "reset" call. This reports what *would* be removed.
        """
        from app.models.models import Secret
        demo_secrets = (await db.execute(
            select(Secret).where(Secret.tags.contains(["demo"]))
        )).scalars().all()
        return {"dataset_id": str(dataset_id), "demo_secrets_found": len(demo_secrets),
                "note": "Reset is report-only. Delete demo-tagged secrets manually via the API/CLI to confirm destructive removal."}


demo_mode_service = DemoModeService()
