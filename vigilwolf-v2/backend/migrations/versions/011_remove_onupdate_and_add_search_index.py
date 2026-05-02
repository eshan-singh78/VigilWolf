"""Remove onupdate triggers from phishkits/clusters last_seen; add IOC value index.

DI-3: PhishkitModel.last_seen onupdate=utc_now defeated explicit updates.
DI-4: ClusterModel.last_seen had the same problem.
H-5:  IocModel.value had no index for LIKE queries.

The onupdate removal is a Python-side (ORM) change with no database
migration needed — SQLAlchemy onupdate is not a database trigger.

The IOC value index is a real database change: a B-tree index on
iocs.value that helps with exact-match and prefix-match queries.
For full substring (ILIKE '%pattern%') search on PostgreSQL, a
pg_trgm GIN index should be added in a future production migration.

Revision ID: 011_remove_onupdate_add_ioc_index
Revises: 010_cluster_last_campaign_check
Create Date: 2026-05-02
"""

from alembic import op


revision = "011_remove_onupdate_add_ioc_index"
down_revision = "010_cluster_last_campaign_check"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "ix_ioc_value",
        "iocs",
        ["value"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ioc_value", table_name="iocs")