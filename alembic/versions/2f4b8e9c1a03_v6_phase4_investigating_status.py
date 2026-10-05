"""v6_phase4_investigating_status

Adds INVESTIGATING to AIFindingStatus. Dialect-conditional: PostgreSQL
requires ALTER TYPE ... ADD VALUE; SQLite has no CHECK constraint on this
column so it's a no-op there (verified empirically).

Revision ID: 2f4b8e9c1a03
Revises: 1e86a6d0d611
Create Date: 2026-08-13
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "2f4b8e9c1a03"
down_revision: Union[str, None] = "1e86a6d0d611"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE aifindingstatus ADD VALUE IF NOT EXISTS 'INVESTIGATING'")
    # SQLite: no-op — status column has no CHECK constraint


def downgrade() -> None:
    pass  # PostgreSQL does not support removing enum values without a full type rebuild
