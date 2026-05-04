"""add CHECK constraints for status columns

Revision ID: 018_add_status_check_constraints
Revises: 017_add_dns_record_unique_constraint
Create Date: 2026-05-04
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "018_add_status_check_constraints"
down_revision = "017_add_dns_record_unique_constraint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE domain_processing_state "
        "ADD CONSTRAINT chk_status CHECK (status IN ('pending','processing','done','failed'))"
    )
    op.execute(
        "ALTER TABLE domain_processing_state "
        "ADD CONSTRAINT chk_priority CHECK (priority IN ('high','low'))"
    )
    op.execute(
        "ALTER TABLE snapshot_plugin_status "
        "ADD CONSTRAINT chk_sps_status CHECK (status IN ('pending','running','done','failed','queued','skipped'))"
    )
    op.execute(
        "ALTER TABLE campaigns "
        "ADD CONSTRAINT chk_campaign_status CHECK (status IN ('active','dormant','closed'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE campaigns DROP CONSTRAINT chk_campaign_status")
    op.execute("ALTER TABLE snapshot_plugin_status DROP CONSTRAINT chk_sps_status")
    op.execute("ALTER TABLE domain_processing_state DROP CONSTRAINT chk_priority")
    op.execute("ALTER TABLE domain_processing_state DROP CONSTRAINT chk_status")