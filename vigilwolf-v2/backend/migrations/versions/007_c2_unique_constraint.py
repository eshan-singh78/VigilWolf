"""Add unique constraint on c2_candidates(ioc_id, snapshot_id).

Revision ID: 007_c2_unique
Revises: 006_c2_candidates_table
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa

revision = "007_c2_unique"
down_revision = "006_c2_candidates_table"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_c2_candidate_snapshot", "c2_candidates", ["ioc_id", "snapshot_id"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_c2_candidate_snapshot", "c2_candidates", type_="unique")