"""initial_v2_schema

Revision ID: 001_initial_v2_schema
Revises:
Create Date: 2026-04-28

This is the initial migration capturing the full v2 schema — both v1
compatibility models (groups, domains, snapshots, ping_logs, dump_logs) and
all v2 additions (processing state, IPs, DNS, analysis, scoring, webhooks,
alerts, feedback, audit).

All 16 tables are created in dependency order.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_v2_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- v1 compatibility tables (no FK dependencies) ----
    op.create_table(
        "groups",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "webhooks",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("secret", sa.Text(), nullable=True),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # ---- domains depends on groups ----
    op.create_table(
        "domains",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("group_id", sa.String(36), sa.ForeignKey("groups.id"), nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("dump_mode", sa.String(20), nullable=False, server_default="html_only"),
        sa.Column("frequency_seconds", sa.Integer(), nullable=False, server_default=sa.text("3600")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("last_checked_at", sa.DateTime(), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("1")),
    )

    # ---- snapshots depends on domains ----
    op.create_table(
        "snapshots",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("trigger_type", sa.String(20), nullable=False),
        sa.Column("html_path", sa.Text(), nullable=False),
        sa.Column("screenshot_path", sa.Text(), nullable=True),
        sa.Column("assets_dir", sa.Text(), nullable=True),
        sa.Column("asset_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("retention_flag", sa.String(20), nullable=False, server_default="standard"),
        sa.Column("success", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.UniqueConstraint("domain_id", "sha256", name="uq_snapshot_domain_sha256"),
    )

    # ---- v1 log tables depend on domains ----
    op.create_table(
        "ping_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("reachable", sa.Boolean(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("change_detected", sa.Boolean(), nullable=False, server_default=sa.text("0")),
        sa.Column("message", sa.Text(), nullable=False),
    )

    op.create_table(
        "dump_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.Column("trigger_type", sa.String(20), nullable=False),
        sa.Column("snapshot_id", sa.String(36), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
    )

    # ---- v2 tables that depend on domains ----
    op.create_table(
        "domain_processing_state",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), unique=True, nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("last_processed_at", sa.DateTime(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("priority", sa.String(10), nullable=False, server_default="low"),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "domain_ips",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("ip", sa.String(45), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("domain_id", "ip", name="uq_domain_ip"),
    )

    op.create_table(
        "dns_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("domain_id", sa.String(36), sa.ForeignKey("domains.id"), nullable=False),
        sa.Column("type", sa.String(10), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
    )

    # ---- v2 tables that depend on snapshots ----
    op.create_table(
        "snapshot_plugin_status",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id"), nullable=False),
        sa.Column("plugin_name", sa.String(50), nullable=False),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.UniqueConstraint("snapshot_id", "plugin_name", name="uq_snapshot_plugin"),
    )

    op.create_table(
        "analysis_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id"), nullable=False),
        sa.Column("plugin_name", sa.String(50), nullable=False),
        sa.Column("plugin_version", sa.String(20), nullable=False),
        sa.Column("plugin_type", sa.String(20), nullable=False),
        sa.Column("result_json", sa.JSON(), nullable=False),
        sa.Column("score_contribution", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("snapshot_id", "plugin_name", name="uq_analysis_snapshot_plugin"),
    )

    op.create_table(
        "risk_scores",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id"), unique=True, nullable=False),
        sa.Column("total_score", sa.Integer(), nullable=False),
        sa.Column("normalized_score", sa.Float(), nullable=False),
        sa.Column("risk_level", sa.String(10), nullable=False),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("dominant_signals", sa.JSON(), nullable=False),
        sa.Column("plugin_breakdown", sa.JSON(), nullable=False),
        sa.Column("overall_confidence", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # ---- standalone v2 tables (no FK dependencies) ----
    op.create_table(
        "plugin_weights",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("plugin_name", sa.String(50), unique=True, nullable=False),
        sa.Column("weight", sa.Float(), nullable=False, server_default=sa.text("1.0")),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("1")),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("actor_id", sa.String(100), nullable=True),
        sa.Column("resource_type", sa.String(50), nullable=True),
        sa.Column("resource_id", sa.String(100), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # ---- alerts depends on domains, snapshots, webhooks ----
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("dedup_key", sa.String(200), nullable=False),
        sa.Column(
            "domain_id", sa.String(36),
            sa.ForeignKey("domains.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "snapshot_id", sa.String(36),
            sa.ForeignKey("snapshots.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("risk_level", sa.String(10), nullable=True),
        sa.Column("severity", sa.String(10), nullable=False),
        sa.Column("score", sa.Integer(), nullable=True),
        sa.Column("campaign_id", sa.String(36), nullable=True),
        sa.Column(
            "webhook_id", sa.String(36),
            sa.ForeignKey("webhooks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("payload_version", sa.String(10), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="sent"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("last_attempt_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )

    # ---- analyst_feedback depends on snapshots ----
    op.create_table(
        "analyst_feedback",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("snapshot_id", sa.String(36), sa.ForeignKey("snapshots.id"), nullable=False),
        sa.Column("label", sa.String(20), nullable=False),
        sa.Column("analyst_id", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    # Drop in reverse dependency order — leaf tables first.
    op.drop_table("analyst_feedback")
    op.drop_table("alerts")
    op.drop_table("audit_logs")
    op.drop_table("plugin_weights")
    op.drop_table("risk_scores")
    op.drop_table("analysis_results")
    op.drop_table("snapshot_plugin_status")
    op.drop_table("dns_records")
    op.drop_table("domain_ips")
    op.drop_table("domain_processing_state")
    op.drop_table("dump_logs")
    op.drop_table("ping_logs")
    op.drop_table("snapshots")
    op.drop_table("domains")
    op.drop_table("webhooks")
    op.drop_table("groups")