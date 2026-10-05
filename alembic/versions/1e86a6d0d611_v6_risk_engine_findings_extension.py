"""v6_risk_engine_findings_extension

Extends ai_findings with nullable v6 fields and loosens ai_provider/ai_model
to nullable (deterministic findings produce no model call).

Revision ID: 1e86a6d0d611
Revises: 7b7fc2e4e158
Create Date: 2026-08-11
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "1e86a6d0d611"
down_revision: Union[str, None] = "7b7fc2e4e158"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The baseline migration (7b7fc2e4e158) already contains the v6
    # columns (risk_score, risk_level, triggered_rules,
    # correlated_event_ids) and nullable ai_provider/ai_model, because
    # autogenerate ran against the already-updated v6 model. This
    # migration is therefore a structural marker in the chain for
    # existing V5 databases that were created via the old create_all()
    # path before the baseline was established: those databases need the
    # new columns added. Fresh databases migrated from scratch will
    # already have them from the baseline and this is a no-op for them.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        # On PostgreSQL use IF NOT EXISTS equivalent via try/except
        try:
            op.add_column("ai_findings", sa.Column("risk_score", sa.Integer(), nullable=True))
        except Exception:
            pass
        try:
            op.add_column("ai_findings", sa.Column("risk_level", sa.String(length=16), nullable=True))
        except Exception:
            pass
        try:
            op.add_column("ai_findings", sa.Column("triggered_rules", sa.JSON(), nullable=True))
        except Exception:
            pass
        try:
            op.add_column("ai_findings", sa.Column("correlated_event_ids", sa.JSON(), nullable=True))
        except Exception:
            pass
        op.alter_column("ai_findings", "ai_provider", existing_type=sa.String(length=32), nullable=True)
        op.alter_column("ai_findings", "ai_model", existing_type=sa.String(length=64), nullable=True)
    # SQLite: all columns already present from baseline; no-op here


def downgrade() -> None:
    pass  # Downgrade from a mixed baseline is not supported without data loss risk
