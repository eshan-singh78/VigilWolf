"""add c2_candidates table for persisting C2 detection results

Revision ID: 006_c2_candidates_table
Revises: 005_phishkit_unique_constraint
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


revision = "006_c2_candidates_table"
down_revision = "005_phishkit_unique_constraint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "c2_candidates",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=True),
        sa.Column("c2_score", sa.Float(), nullable=False),
        sa.Column("signals", sa.JSON(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_c2_candidates_score", "c2_candidates", ["c2_score"], unique=False)
    op.create_index("ix_c2_candidates_ioc_id", "c2_candidates", ["ioc_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_c2_candidates_ioc_id", table_name="c2_candidates")
    op.drop_index("ix_c2_candidates_score", table_name="c2_candidates")
    op.drop_table("c2_candidates")