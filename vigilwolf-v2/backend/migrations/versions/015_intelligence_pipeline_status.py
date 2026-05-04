"""add intelligence_pipeline_status table

Revision ID: 015_intelligence_pipeline_status
Revises: 014_remove_onupdate_domain_processing_plugin_weight
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "015_intelligence_pipeline_status"
down_revision = "014_remove_onupdate_domain_processing_plugin_weight"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "intelligence_pipeline_status",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stage", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.UniqueConstraint("snapshot_id", "stage", name="uq_intel_pipeline_snapshot_stage"),
    )


def downgrade() -> None:
    op.drop_table("intelligence_pipeline_status")