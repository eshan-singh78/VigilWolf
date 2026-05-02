"""add performance indexes for read-heavy endpoints

Revision ID: 003_performance_indexes
Revises: 002_intelligence_tables
Create Date: 2026-05-01
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "003_performance_indexes"
down_revision = "002_intelligence_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_snapshots_domain_timestamp",
        "snapshots",
        ["domain_id", "timestamp"],
        unique=False,
    )
    op.create_index(
        "ix_risk_scores_snapshot_risk",
        "risk_scores",
        ["snapshot_id", "risk_level"],
        unique=False,
    )
    op.create_index(
        "ix_alerts_filters",
        "alerts",
        ["severity", "status", "risk_level", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_filters", table_name="alerts")
    op.drop_index("ix_risk_scores_snapshot_risk", table_name="risk_scores")
    op.drop_index("ix_snapshots_domain_timestamp", table_name="snapshots")
