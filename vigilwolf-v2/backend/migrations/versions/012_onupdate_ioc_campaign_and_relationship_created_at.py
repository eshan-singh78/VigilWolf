"""Remove onupdate triggers from iocs/campaigns/actors last_seen; add created_at to ioc_relationships.

C-2:  IocModel.last_seen onupdate=utc_now silently overrode explicit
      updates from ioc_service.py. Removed onupdate; kept default.
DI-1: CampaignModel.last_seen and ActorModel.last_seen had the same
      problem. Removed onupdate from both; kept default and nullable=False.
S-3:  IocRelationshipModel lacked a created_at column, preventing
      age-out of stale relationships. Added created_at as
      DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL.

The onupdate removals are Python-side (ORM) changes with no database
migration needed -- SQLAlchemy onupdate is not a database trigger,
so no SQL ALTER is required to drop it.

The created_at column and index are real database changes.

Revision ID: 012_onupdate_ioc_campaign_rel_created_at
Revises: 011_remove_onupdate_add_ioc_index
Create Date: 2026-05-02
"""

from alembic import op
import sqlalchemy as sa


revision = "012_onupdate_ioc_campaign_rel_created_at"
down_revision = "011_remove_onupdate_add_ioc_index"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "ioc_relationships",
        sa.Column(
            "created_at",
            sa.DateTime(),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_ioc_relationships_created_at",
        "ioc_relationships",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ioc_relationships_created_at", table_name="ioc_relationships")
    op.drop_column("ioc_relationships", "created_at")