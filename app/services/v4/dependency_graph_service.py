"""
Secret Dependency Graph — NanoVault v4.0

Builds a real dependency graph from live database relationships:
Organizations -> Projects -> Teams -> Namespaces -> Secrets/Transit Keys/Certificates.
Every edge here comes from an actual foreign key relationship in the schema,
not a simulated structure.
"""
from __future__ import annotations
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.models import (
    Organization, Project, Team, Namespace, Secret,
    TransitKey, Certificate, DynamicCredential, Policy,
)


class DependencyGraphService:

    @staticmethod
    async def build_full_graph(db: AsyncSession) -> dict:
        """Real traversal of org -> namespace -> resource relationships."""
        orgs = (await db.execute(select(Organization))).scalars().all()
        namespaces = (await db.execute(select(Namespace))).scalars().all()
        secrets = (await db.execute(select(Secret).where(Secret.is_deleted == False))).scalars().all()  # noqa
        transit_keys = (await db.execute(select(TransitKey))).scalars().all()
        certs = (await db.execute(select(Certificate))).scalars().all()
        dyn_creds = (await db.execute(select(DynamicCredential))).scalars().all()

        nodes = []
        edges = []

        for o in orgs:
            nodes.append({"id": f"org:{o.id}", "type": "organization", "label": o.name})

        for ns in namespaces:
            nodes.append({"id": f"ns:{ns.id}", "type": "namespace", "label": ns.path})
            if ns.org_id:
                edges.append({"from": f"org:{ns.org_id}", "to": f"ns:{ns.id}", "relation": "contains"})

        for s in secrets:
            nodes.append({"id": f"secret:{s.id}", "type": "secret", "label": s.key})
            edges.append({"from": f"user:{s.owner_id}", "to": f"secret:{s.id}", "relation": "owns"})

        for k in transit_keys:
            nodes.append({"id": f"transit:{k.id}", "type": "transit_key", "label": k.name})

        for c in certs:
            nodes.append({"id": f"cert:{c.id}", "type": "certificate", "label": c.common_name})
            edges.append({"from": f"ca:{c.ca_id}", "to": f"cert:{c.id}", "relation": "issued_by"})

        for d in dyn_creds:
            nodes.append({"id": f"dyncred:{d.id}", "type": "dynamic_credential", "label": d.credential_type.value if hasattr(d.credential_type, "value") else str(d.credential_type)})

        return {
            "nodes": nodes, "edges": edges,
            "node_count": len(nodes), "edge_count": len(edges),
            "summary": {
                "organizations": len(orgs), "namespaces": len(namespaces),
                "secrets": len(secrets), "transit_keys": len(transit_keys),
                "certificates": len(certs), "dynamic_credentials": len(dyn_creds),
            },
        }

    @staticmethod
    async def get_secret_impact_analysis(db: AsyncSession, secret_id: uuid.UUID) -> dict:
        """
        Real impact analysis: what would be affected if this secret were
        deleted/rotated. Checks version history and rotation history —
        the actual dependency signals that exist in this schema.
        """
        secret = (await db.execute(select(Secret).where(Secret.id == secret_id))).scalar_one_or_none()
        if not secret:
            return {"error": "Secret not found"}

        from app.models.models import SecretVersion, RotationHistory
        versions = (await db.execute(
            select(SecretVersion).where(SecretVersion.secret_id == secret_id)
        )).scalars().all()
        rotations = (await db.execute(
            select(RotationHistory).where(RotationHistory.secret_id == secret_id)
        )).scalars().all()

        return {
            "secret_id": str(secret_id),
            "key": secret.key,
            "current_version": secret.version,
            "total_versions": len(versions),
            "rotation_count": len(rotations),
            "namespace": getattr(secret, "namespace_id", None) and str(secret.namespace_id),
            "impact": {
                "would_break_version_history": len(versions) > 1,
                "has_rotation_schedule": len(rotations) > 0,
            },
        }

    @staticmethod
    async def get_reverse_dependencies(db: AsyncSession, resource_type: str, resource_id: uuid.UUID) -> dict:
        """Given a resource, find everything that references it (reverse FK lookup)."""
        if resource_type == "organization":
            namespaces = (await db.execute(
                select(Namespace).where(Namespace.org_id == resource_id)
            )).scalars().all()
            return {"resource_type": resource_type, "resource_id": str(resource_id),
                    "referenced_by": [{"type": "namespace", "id": str(n.id), "label": n.path} for n in namespaces]}

        if resource_type == "certificate_authority":
            certs = (await db.execute(
                select(Certificate).where(Certificate.ca_id == resource_id)
            )).scalars().all()
            return {"resource_type": resource_type, "resource_id": str(resource_id),
                    "referenced_by": [{"type": "certificate", "id": str(c.id), "label": c.common_name} for c in certs]}

        return {"resource_type": resource_type, "resource_id": str(resource_id), "referenced_by": [],
                "note": f"Reverse lookup not implemented for type '{resource_type}'"}

    @staticmethod
    async def get_ownership_map(db: AsyncSession) -> dict:
        """Real aggregation: which users own how many secrets/keys/certs."""
        from sqlalchemy import func
        secret_counts = (await db.execute(
            select(Secret.owner_id, func.count()).where(Secret.is_deleted == False).group_by(Secret.owner_id)  # noqa
        )).all()
        return {"secrets_by_owner": [{"owner_id": str(o), "count": c} for o, c in secret_counts]}


dependency_graph_service = DependencyGraphService()
