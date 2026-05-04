"""add clustering watermark table for incremental processing

Revision ID: 005_clustering_watermark
Revises: 004_pipeline_status
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "005_clustering_watermark"
down_revision = "005_phishkit_unique_constraint"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clustering_watermarks",
        sa.Column("id", sa.String(50), primary_key=True),
        sa.Column("last_processed_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("clustering_watermarks")