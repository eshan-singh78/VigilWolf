"""add unique constraint on phishkits.signature_hash

Revision ID: 005_phishkit_unique_constraint
Revises: 005_clustering_watermark
Create Date: 2026-05-02
"""

from alembic import op


revision = "005_phishkit_unique_constraint"
down_revision = "005_clustering_watermark"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_phishkit_signature", "phishkits", ["signature_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_phishkit_signature", "phishkits", type_="unique")