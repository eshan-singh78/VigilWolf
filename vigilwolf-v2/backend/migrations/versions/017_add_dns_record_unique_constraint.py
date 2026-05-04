"""add unique constraint on dns_records(domain_id, type, value)

Revision ID: 017_add_dns_record_unique_constraint
Revises: 016_add_domain_and_alert_unique_constraints
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "017_add_dns_record_unique_constraint"
down_revision = "016_add_domain_and_alert_unique_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_dns_records_domain_type_value",
        "dns_records",
        ["domain_id", "type", "value"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_dns_records_domain_type_value", table_name="dns_records")