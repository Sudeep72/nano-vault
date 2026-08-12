"""
Natural-Language Security Search — NanoVault v5.0 (Step 6)

Additive to the existing deterministic secret_service.search — this is a
new capability, not a replacement. AI's job here is narrow and specific:
classify which existing, RBAC-respecting context sources are relevant to
a natural-language question, gather from ONLY those (never raw SQL from
the model), and produce a structured, sourced answer.

The AI never generates or executes a database query itself — that would
be an unacceptable injection surface for a security product. It only
selects among a fixed, pre-approved set of context-gathering functions.
"""
from __future__ import annotations
from sqlalchemy.ext.asyncio import AsyncSession
from app.services.v5.security_context_service import security_context_service
from app.services.v5.ai_security_engine import ai_security_engine
from app.services.v5.guardrails_service import sanitize_user_query

# Fixed, pre-approved set of context sources — the model can only pick
# from this list via keyword matching, never invent a new query surface.
_SOURCE_KEYWORDS = {
    "audit": ["login", "authentication", "auth", "audit", "activity", "access", "event"],
    "architecture": ["service", "engine", "depend", "architecture", "component", "seal"],
    "policy": ["policy", "permission", "rbac", "violation", "rule"],
    "secrets": ["secret", "key rotation", "credential metadata"],
    "identity": ["identity", "provider", "ldap", "oidc", "saml"],
    "health": ["health", "status", "unhealthy", "degraded"],
}


class AISearchService:

    @staticmethod
    def _select_sources(query: str) -> list[str]:
        """Deterministic keyword routing — NOT an AI call. Keeps source
        selection auditable and immune to prompt injection since it never
        touches the model."""
        q = query.lower()
        matched = [src for src, kws in _SOURCE_KEYWORDS.items() if any(k in q for k in kws)]
        return matched or ["audit"]  # default to audit trail if nothing matches

    @staticmethod
    async def search(db: AsyncSession, current_user, query: str) -> dict:
        query = sanitize_user_query(query)
        sources = AISearchService._select_sources(query)

        context_items: list[dict] = []
        if "audit" in sources:
            context_items.extend(await security_context_service.gather_audit_context(db, current_user, limit=30))
        if "architecture" in sources:
            context_items.extend(await security_context_service.gather_architecture_context())
        if "policy" in sources:
            context_items.extend(await security_context_service.gather_policy_context(db, current_user))
        if "secrets" in sources:
            context_items.extend(await security_context_service.gather_secret_metadata_context(db, current_user))
        if "identity" in sources:
            context_items.extend(await security_context_service.gather_identity_context(db))
        if "health" in sources:
            context_items.append(await security_context_service.gather_health_context(db))

        if not context_items:
            return {"success": True, "finding": None,
                    "message": "No permitted data found for this query — either no matching records "
                              "exist, or they are outside your authorization scope."}

        result = await ai_security_engine.run_analysis(
            db, current_user, task="nl_search",
            context_items=context_items, user_query=query, category="nl_search",
        )
        response = result.to_dict()
        response["sources_queried"] = sources
        return response


ai_search_service = AISearchService()
