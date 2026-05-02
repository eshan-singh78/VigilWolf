"""Remove onupdate=utc_now from DomainProcessingStateModel and PluginWeightModel.

DI-2: DomainProcessingStateModel.updated_at had onupdate=utc_now which silently
      overrode explicit updates from application code. Removed onupdate; kept
      default=utc_now and nullable=False.
DI-3: PluginWeightModel.updated_at had the same problem. Removed onupdate;
      kept default=utc_now and nullable=False.

These are Python-side (ORM) changes only. SQLAlchemy onupdate is not a
database trigger, so no SQL ALTER is required.

Revision ID: 014_remove_onupdate_domain_processing_plugin_weight
Revises: 013_c2_candidate_ioc_unique
Create Date: 2026-05-02
"""

from alembic import op


revision = "014_remove_onupdate_domain_processing_plugin_weight"
down_revision = "013_c2_candidate_ioc_unique"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # No database changes needed -- onupdate removal is ORM-side only.
    pass


def downgrade() -> None:
    # No database changes needed -- onupdate removal is ORM-side only.
    pass