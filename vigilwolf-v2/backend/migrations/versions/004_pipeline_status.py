"""add intelligence pipeline status tracking table

Revision ID: 004_pipeline_status
Revises: 004_intelligence_unique_constraints
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "004_pipeline_status"
down_revision = "004_intelligence_unique_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intelligence_pipeline_status",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stage", sa.String(30), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("snapshot_id", "stage", name="uq_pipeline_status_snapshot_stage"),
    )


def downgrade() -> None:
    op.drop_table("intelligence_pipeline_status")