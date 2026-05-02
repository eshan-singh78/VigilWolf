"""add unique constraints to intelligence tables for idempotent writes

Revision ID: 004_intelligence_unique_constraints
Revises: 003_performance_indexes
Create Date: 2026-05-02
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "004_intelligence_unique_constraints"
down_revision = "003_performance_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_ioc_occurrence_snapshot", "ioc_occurrences", ["ioc_id", "snapshot_id"],
    )
    op.create_unique_constraint(
        "uq_ioc_relationship", "ioc_relationships",
        ["source_ioc_id", "target_ioc_id", "relationship_type"],
    )
    op.create_unique_constraint(
        "uq_cluster_signature", "clusters",
        ["cluster_type", "signature_hash", "signature_type"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_cluster_signature", "clusters", type_="unique")
    op.drop_constraint("uq_ioc_relationship", "ioc_relationships", type_="unique")
    op.drop_constraint("uq_ioc_occurrence_snapshot", "ioc_occurrences", type_="unique")