"""add asn and registrar columns, remove clustering watermark onupdate

Revision ID: 015_add_asn_registrar_columns
Revises: 014_remove_onupdate_domain_processing_plugin_weight
Create Date: 2026-05-04
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "015_add_asn_registrar_columns"
down_revision = "014_remove_onupdate_domain_processing_plugin_weight"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("domain_ips", sa.Column("asn", sa.String(20), nullable=True))
    op.add_column("domains", sa.Column("registrar", sa.String(200), nullable=True))


def downgrade() -> None:
    op.drop_column("domains", "registrar")
    op.drop_column("domain_ips", "asn")