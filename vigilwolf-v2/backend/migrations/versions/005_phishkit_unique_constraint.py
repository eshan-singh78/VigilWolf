"""add unique constraint on phishkits.signature_hash

Revision ID: 005_phishkit_unique_constraint
Revises: 004_intelligence_unique_constraints
Create Date: 2026-05-02
"""

from alembic import op


revision = "005_phishkit_unique_constraint"
down_revision = "004_intelligence_unique_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_phishkit_signature", "phishkits", ["signature_hash"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_phishkit_signature", "phishkits", type_="unique")