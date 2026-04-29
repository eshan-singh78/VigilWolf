"""Phase 2-4: IOC, clustering, phishkit, campaign, actor tables.

Revision ID: 002
Revises: 001
"""
from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # --- Phase 2: IOC tables ---
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value"),
    )
    op.create_index("idx_iocs_type_value", "iocs", ["type", "value"])

    op.create_table(
        "ioc_occurrences",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("ioc_id", sa.Integer(), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("context", sa.String(20), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("role", sa.String(30), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_ioc_occurrences_snapshot", "ioc_occurrences", ["snapshot_id"])
    op.create_index("idx_ioc_occurrences_ioc", "ioc_occurrences", ["ioc_id"])

    op.create_table(
        "ioc_relationships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_ioc_id", sa.Integer(), nullable=False),
        sa.Column("target_ioc_id", sa.Integer(), nullable=False),
        sa.Column("relationship_type", sa.String(30), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["source_ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_ioc_id"], ["iocs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    # --- Phase 2: Clustering tables ---
    op.create_table(
        "clusters",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("cluster_type", sa.String(30), nullable=False),
        sa.Column("signature_hash", sa.Text(), nullable=False),
        sa.Column("signature_type", sa.String(30), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("domain_count", sa.Integer(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_cluster_type", "clusters", ["cluster_type"])
    op.create_index("idx_cluster_signature", "clusters", ["signature_hash", "signature_type"])

    op.create_table(
        "cluster_members",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("cluster_id", sa.String(36), nullable=False),
        sa.Column("domain_id", sa.String(36), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["cluster_id"], ["clusters.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cluster_id", "domain_id"),
    )
    op.create_index("idx_cluster_members_domain", "cluster_members", ["domain_id"])
    op.create_index("idx_cluster_members_cluster", "cluster_members", ["cluster_id"])

    # --- Phase 3: PhishKit tables ---
    op.create_table(
        "phishkits",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("signature_hash", sa.Text(), nullable=True),
        sa.Column("panel_path", sa.Text(), nullable=True),
        sa.Column("exfil_endpoint", sa.Text(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("signature_hash"),
    )

    op.create_table(
        "snapshot_phishkits",
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("phishkit_id", sa.String(36), nullable=False),
        sa.Column("similarity", sa.Float(), nullable=True),
        sa.ForeignKeyConstraint(["snapshot_id"], ["snapshots.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["phishkit_id"], ["phishkits.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("snapshot_id", "phishkit_id"),
    )

    # --- Phase 3: Campaign tables ---
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("target_brand", sa.String(100), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("domain_count", sa.Integer(), nullable=True),
        sa.Column("kit_signature", sa.Text(), nullable=True),
        sa.Column("status", sa.String(20), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("idx_campaign_first_seen", "campaigns", ["first_seen"])
    op.create_index("idx_campaign_status", "campaigns", ["status"])

    op.create_table(
        "campaign_clusters",
        sa.Column("campaign_id", sa.String(36), nullable=False),
        sa.Column("cluster_id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["cluster_id"], ["clusters.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("campaign_id", "cluster_id"),
    )

    # --- Phase 4: Actor tables ---
    op.create_table(
        "actors",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("label", sa.String(200), nullable=False),
        sa.Column("fingerprint", sa.JSON(), nullable=False),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("label"),
    )

    op.create_table(
        "actor_campaigns",
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("campaign_id", sa.String(36), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["actors.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("actor_id", "campaign_id"),
    )


def downgrade() -> None:
    op.drop_table("actor_campaigns")
    op.drop_table("actors")
    op.drop_table("campaign_clusters")
    op.drop_table("campaigns")
    op.drop_table("snapshot_phishkits")
    op.drop_table("phishkits")
    op.drop_table("cluster_members")
    op.drop_table("clusters")
    op.drop_table("ioc_relationships")
    op.drop_table("ioc_occurrences")
    op.drop_table("iocs")