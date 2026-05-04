"""add unique constraints on domains(group_id,url) and alerts(dedup_key,webhook_id)

Revision ID: 016_add_domain_and_alert_unique_constraints
Revises: 015_intelligence_pipeline_status
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "016_add_domain_and_alert_unique_constraints"
down_revision = "015_intelligence_pipeline_status"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Use create_index with unique=True instead of create_unique_constraint
    # to handle existing duplicate rows gracefully (PostgreSQL will raise
    # an error on create_unique_constraint if duplicates exist, but
    # create_index CONCURRENTLY can be run after manual dedup).
    op.create_index(
        "ix_domains_group_url",
        "domains",
        ["group_id", "url"],
        unique=True,
    )
    op.create_index(
        "ix_alerts_dedup_webhook",
        "alerts",
        ["dedup_key", "webhook_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_alerts_dedup_webhook", table_name="alerts")
    op.drop_index("ix_domains_group_url", table_name="domains")