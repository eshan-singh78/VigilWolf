"""Add composite index on analysis_results(plugin_name, snapshot_id).

Revision ID: 009_analysis_result_composite
Revises: 007_c2_unique
Create Date: 2026-05-02
"""

from alembic import op


revision = "009_analysis_result_composite"
down_revision = "007_c2_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_analysis_result_plugin_snapshot",
        "analysis_results",
        ["plugin_name", "snapshot_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_analysis_result_plugin_snapshot", table_name="analysis_results")