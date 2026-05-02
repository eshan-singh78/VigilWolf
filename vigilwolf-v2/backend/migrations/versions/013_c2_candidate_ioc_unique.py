"""Change C2 candidate unique constraint from (ioc_id, snapshot_id) to (ioc_id).

FS-2: The old (ioc_id, snapshot_id) constraint allowed duplicate rows for the
same IOC across different snapshot_ids, causing unbounded row growth.  The
intelligence worker now deduplicates by ioc_id alone (updating score in-place),
so uniqueness should be on ioc_id only.  The snapshot_id column is kept because
it records which snapshot triggered the detection.

Revision ID: 013_c2_candidate_ioc_unique
Revises: 012_onupdate_ioc_campaign_rel_created_at
Create Date: 2026-05-02
"""

from alembic import op


revision = "013_c2_candidate_ioc_unique"
down_revision = "012_onupdate_ioc_campaign_rel_created_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("uq_c2_candidate_snapshot", "c2_candidates", type_="unique")
    op.create_unique_constraint("uq_c2_candidate_ioc", "c2_candidates", ["ioc_id"])


def downgrade() -> None:
    op.drop_constraint("uq_c2_candidate_ioc", "c2_candidates", type_="unique")
    op.create_unique_constraint("uq_c2_candidate_snapshot", "c2_candidates", ["ioc_id", "snapshot_id"])