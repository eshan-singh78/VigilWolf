"""Add last_campaign_check column to clusters table.

Revision ID: 010_cluster_last_campaign_check
Revises: 009_analysis_result_composite
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


revision = "010_cluster_last_campaign_check"
down_revision = "009_analysis_result_composite"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "clusters",
        sa.Column("last_campaign_check", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("clusters", "last_campaign_check")