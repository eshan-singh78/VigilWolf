"""VigilWolf v2 — SQLAlchemy ORM models.

This module defines the complete database schema, including v1 compatibility
models (GroupModel, DomainModel, SnapshotModel, PingLogModel, DumpLogModel)
and all new v2 models (processing state, IPs, DNS, analysis, scoring,
webhooks, alerts, feedback, audit).

SQLite is used for development/testing; PostgreSQL for production.
All column types are chosen for SQLite compatibility (e.g. String instead of
PostgreSQL-native INET, JSON instead of JSONB).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import List

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    JSON,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker, Session
from sqlalchemy.pool import StaticPool

import config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    """Declarative base for all ORM models."""
    pass


# ---------------------------------------------------------------------------
# v1 Compatibility Models
# ---------------------------------------------------------------------------

class GroupModel(Base):
    """A logical grouping of monitored domains (v1 compatibility)."""
    __tablename__ = "groups"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # relationships
    domains = relationship("DomainModel", back_populates="group", lazy="dynamic")


class DomainModel(Base):
    """A monitored domain / URL (v1 compatibility + v2 extensions)."""
    __tablename__ = "domains"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    group_id = Column(String(36), ForeignKey("groups.id"), nullable=False)
    url = Column(Text, nullable=False)
    dump_mode = Column(String(20), nullable=False, default="html_only")
    frequency_seconds = Column(Integer, nullable=False, default=3600)
    created_at = Column(DateTime, default=utc_now, nullable=False)
    last_checked_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True, nullable=False)

    # relationships
    group = relationship("GroupModel", back_populates="domains")
    snapshots = relationship("SnapshotModel", back_populates="domain", lazy="dynamic")
    ping_logs = relationship("PingLogModel", back_populates="domain", lazy="dynamic")
    dump_logs = relationship("DumpLogModel", back_populates="domain", lazy="dynamic")
    processing_state = relationship(
        "DomainProcessingStateModel", back_populates="domain", uselist=False,
    )
    ips = relationship("DomainIpModel", back_populates="domain", lazy="dynamic")
    dns_records = relationship("DnsRecordModel", back_populates="domain", lazy="dynamic")
    cluster_memberships = relationship("ClusterMemberModel", back_populates="domain", lazy="dynamic")


class SnapshotModel(Base):
    """A captured snapshot of a domain (v1 compatibility + v2 extensions)."""
    __tablename__ = "snapshots"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    domain_id = Column(String(36), ForeignKey("domains.id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    trigger_type = Column(String(20), nullable=False)
    html_path = Column(Text, nullable=False)
    screenshot_path = Column(Text, nullable=True)
    assets_dir = Column(Text, nullable=True)
    asset_count = Column(Integer, default=0, nullable=False)
    sha256 = Column(String(64), nullable=True)
    size_bytes = Column(BigInteger, default=0, nullable=False)
    retention_flag = Column(String(20), default="standard", nullable=False)
    success = Column(Boolean, default=True, nullable=False)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("domain_id", "sha256", name="uq_snapshot_domain_sha256"),
    )

    # relationships
    domain = relationship("DomainModel", back_populates="snapshots")
    analysis_results = relationship("AnalysisResultModel", back_populates="snapshot", lazy="dynamic")
    risk_score = relationship("RiskScoreModel", back_populates="snapshot", uselist=False)
    ioc_occurrences = relationship("IocOccurrenceModel", back_populates="snapshot", lazy="dynamic")
    plugin_statuses = relationship("SnapshotPluginStatusModel", back_populates="snapshot", lazy="dynamic")


class PingLogModel(Base):
    """Ping/availability log entry (v1 compatibility)."""
    __tablename__ = "ping_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey("domains.id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    reachable = Column(Boolean, nullable=False)
    status_code = Column(Integer, nullable=True)
    change_detected = Column(Boolean, nullable=False, default=False)
    message = Column(Text, nullable=False)

    # relationships
    domain = relationship("DomainModel", back_populates="ping_logs")


class DumpLogModel(Base):
    """Dump/snapshot log entry (v1 compatibility)."""
    __tablename__ = "dump_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey("domains.id"), nullable=False)
    timestamp = Column(DateTime, default=utc_now, nullable=False)
    trigger_type = Column(String(20), nullable=False)
    snapshot_id = Column(String(36), nullable=False)
    success = Column(Boolean, nullable=False)
    error_message = Column(Text, nullable=True)
    message = Column(Text, nullable=False)

    # relationships
    domain = relationship("DomainModel", back_populates="dump_logs")


# ---------------------------------------------------------------------------
# v2 New Models
# ---------------------------------------------------------------------------

class DomainProcessingStateModel(Base):
    """Tracks the processing pipeline state for each domain."""
    __tablename__ = "domain_processing_state"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(
        String(36), ForeignKey("domains.id"), unique=True, nullable=False,
    )
    status = Column(
        String(20), nullable=False, default="pending",
        # CHECK constraint: pending | processing | done | failed
    )
    last_processed_at = Column(DateTime, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)
    priority = Column(
        String(10), nullable=False, default="low",
        # CHECK constraint: high | low
    )
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)

    # relationships
    domain = relationship("DomainModel", back_populates="processing_state")

    __table_args__ = (
        # SQLite doesn't enforce CHECK but we define it for PostgreSQL migrations
        # and documentation purposes.
        # status IN ('pending', 'processing', 'done', 'failed')
        # priority IN ('high', 'low')
    )


class DomainIpModel(Base):
    """IP addresses resolved for a monitored domain."""
    __tablename__ = "domain_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey("domains.id"), nullable=False)
    # PostgreSQL would use INET type here; String for SQLite compatibility.
    ip = Column(String(45), nullable=False)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("domain_id", "ip", name="uq_domain_ip"),
    )

    # relationships
    domain = relationship("DomainModel", back_populates="ips")


class DnsRecordModel(Base):
    """DNS records observed for a monitored domain."""
    __tablename__ = "dns_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain_id = Column(String(36), ForeignKey("domains.id"), nullable=False)
    type = Column(String(10), nullable=False)
    value = Column(Text, nullable=False)
    ttl = Column(Integer, nullable=True)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)

    # relationships
    domain = relationship("DomainModel", back_populates="dns_records")


class SnapshotPluginStatusModel(Base):
    """Per-snapshot plugin execution status."""
    __tablename__ = "snapshot_plugin_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False)
    plugin_name = Column(String(50), nullable=False)
    status = Column(
        String(20), nullable=False, default="pending",
        # CHECK: pending | running | done | failed | timed_out
    )
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("snapshot_id", "plugin_name", name="uq_snapshot_plugin"),
    )

    # relationships
    snapshot = relationship("SnapshotModel", back_populates="plugin_statuses")


class AnalysisResultModel(Base):
    """Output from a single plugin analysis run on a snapshot."""
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False)
    plugin_name = Column(String(50), nullable=False)
    plugin_version = Column(String(20), nullable=False)
    plugin_type = Column(
        String(20), nullable=False,
        # CHECK: detection | extraction | enrichment | fingerprint
    )
    result_json = Column(JSON, nullable=False)
    score_contribution = Column(Integer, default=0, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    tags = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    __table_args__ = (
        UniqueConstraint("snapshot_id", "plugin_name", name="uq_analysis_snapshot_plugin"),
        Index('ix_analysis_result_plugin_snapshot', 'plugin_name', 'snapshot_id'),
    )

    # relationships
    snapshot = relationship("SnapshotModel", back_populates="analysis_results")


class RiskScoreModel(Base):
    """Aggregated risk score for a snapshot."""
    __tablename__ = "risk_scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(
        String(36), ForeignKey("snapshots.id"), unique=True, nullable=False,
    )
    total_score = Column(Integer, nullable=False)
    normalized_score = Column(Float, nullable=False)
    risk_level = Column(String(10), nullable=False)
    severity = Column(String(10), nullable=False)
    reasons = Column(JSON, nullable=False)
    dominant_signals = Column(JSON, default=list, nullable=False)
    plugin_breakdown = Column(JSON, default=dict, nullable=False)
    overall_confidence = Column(Float, default=1.0, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # relationships
    snapshot = relationship("SnapshotModel", back_populates="risk_score")


class PluginWeightModel(Base):
    """Configurable weight for each plugin in the scoring formula."""
    __tablename__ = "plugin_weights"

    id = Column(Integer, primary_key=True, autoincrement=True)
    plugin_name = Column(String(50), unique=True, nullable=False)
    weight = Column(Float, default=1.0, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now, nullable=False)


class WebhookModel(Base):
    """Outbound webhook configuration for alert delivery."""
    __tablename__ = "webhooks"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False)
    url = Column(Text, nullable=False)
    secret = Column(Text, nullable=True)
    events = Column(JSON, nullable=False)
    filters = Column(JSON, default=dict, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class AlertModel(Base):
    """An alert dispatched to a webhook endpoint."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(50), nullable=False)
    dedup_key = Column(String(200), nullable=False)
    domain_id = Column(
        String(36), ForeignKey("domains.id", ondelete="SET NULL"), nullable=True,
    )
    snapshot_id = Column(
        String(36), ForeignKey("snapshots.id", ondelete="SET NULL"), nullable=True,
    )
    risk_level = Column(String(10), nullable=True)
    severity = Column(String(10), nullable=False)
    score = Column(Integer, nullable=True)
    campaign_id = Column(String(36), nullable=True)
    webhook_id = Column(
        String(36), ForeignKey("webhooks.id", ondelete="SET NULL"), nullable=True,
    )
    payload = Column(JSON, nullable=False)
    payload_version = Column(String(10), default="1.0", nullable=False)
    status = Column(
        String(20), default="sent", nullable=False,
        # CHECK: sent | failed | retrying
    )
    attempts = Column(Integer, default=0, nullable=False)
    last_attempt_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)

    # relationships (no back_populates needed — these are log-style references)
    domain = relationship("DomainModel")
    snapshot = relationship("SnapshotModel")
    webhook = relationship("WebhookModel")


class AnalystFeedbackModel(Base):
    """Human analyst labels on snapshots (ground truth for scoring)."""
    __tablename__ = "analyst_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id"), nullable=False)
    label = Column(String(20), nullable=False)
    analyst_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)


class AuditLogModel(Base):
    """Append-only audit log for all significant actions."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(100), nullable=False)
    actor_id = Column(String(100), nullable=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utc_now, nullable=False)


# ===========================================================================
# Phase 2 — IOC models
# ===========================================================================

class IocModel(Base):
    """Deduplicated indicator of compromise."""
    __tablename__ = "iocs"
    __table_args__ = (
        UniqueConstraint("value_hash", name="uq_ioc_value_hash"),
        Index("ix_ioc_value", "value"),  # helps with prefix/exact matches
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(20), nullable=False)  # domain, ip, url, email, telegram, wallet, phone
    value = Column(Text, nullable=False)
    value_hash = Column(String(64), nullable=False, index=True)
    first_seen = Column(DateTime, default=utc_now)
    last_seen = Column(DateTime, default=utc_now)

    occurrences = relationship("IocOccurrenceModel", back_populates="ioc", lazy="dynamic")


class IocOccurrenceModel(Base):
    """A specific appearance of an IOC in a snapshot."""
    __tablename__ = "ioc_occurrences"
    __table_args__ = (
        UniqueConstraint("ioc_id", "snapshot_id", name="uq_ioc_occurrence_snapshot"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=False)
    context = Column(String(20), nullable=True)  # script, html, link, form
    confidence = Column(Float, default=1.0)
    role = Column(String(30), nullable=True)  # exfil_endpoint, cdn, tracking, redirect, resource
    created_at = Column(DateTime, default=utc_now, nullable=False)

    ioc = relationship("IocModel", back_populates="occurrences")
    snapshot = relationship("SnapshotModel", back_populates="ioc_occurrences")


class IocRelationshipModel(Base):
    """Relationship between two IOCs (same_page, redirect, script_load, shared_hosting)."""
    __tablename__ = "ioc_relationships"
    __table_args__ = (
        UniqueConstraint("source_ioc_id", "target_ioc_id", "relationship_type", name="uq_ioc_relationship"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    source_ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    target_ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(30), nullable=False)
    confidence = Column(Float, default=1.0)
    created_at = Column(DateTime, default=utc_now, nullable=False)


# ===========================================================================
# Phase 2 — Clustering models
# ===========================================================================

class ClusterModel(Base):
    """A group of related domains (HTML similarity, infrastructure, phishkit, campaign)."""
    __tablename__ = "clusters"
    __table_args__ = (
        UniqueConstraint("cluster_type", "signature_hash", "signature_type", name="uq_cluster_signature"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    cluster_type = Column(String(30), nullable=False)  # html_similarity, infra, phishkit, campaign
    signature_hash = Column(Text, nullable=False)
    signature_type = Column(String(30), nullable=False)  # structural_hash, infra_signature, js_hash
    description = Column(Text, nullable=True)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)
    domain_count = Column(Integer, default=0)
    last_campaign_check = Column(DateTime(timezone=True), nullable=True)
    meta = Column(JSON, default=dict)

    members = relationship("ClusterMemberModel", back_populates="cluster", lazy="dynamic")


class ClusterMemberModel(Base):
    """A domain's membership in a cluster."""
    __tablename__ = "cluster_members"

    id = Column(Integer, primary_key=True, autoincrement=True)
    cluster_id = Column(String(36), ForeignKey("clusters.id", ondelete="CASCADE"), nullable=False)
    domain_id = Column(String(36), ForeignKey("domains.id", ondelete="CASCADE"), nullable=False)
    confidence = Column(Float, default=1.0)
    joined_at = Column(DateTime, default=utc_now, nullable=False)

    cluster = relationship("ClusterModel", back_populates="members")
    domain = relationship("DomainModel", back_populates="cluster_memberships")

    __table_args__ = (UniqueConstraint("cluster_id", "domain_id"),)


# ===========================================================================
# Phase 3 — PhishKit models
# ===========================================================================

class PhishkitModel(Base):
    """A detected phishing kit identified by JS/DOM signature."""
    __tablename__ = "phishkits"
    __table_args__ = (
        UniqueConstraint("signature_hash", name="uq_phishkit_signature"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    signature_hash = Column(Text, nullable=False)
    panel_path = Column(Text, nullable=True)
    exfil_endpoint = Column(Text, nullable=True)
    meta = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)


class SnapshotPhishkitModel(Base):
    """Association between a snapshot and a detected phishkit."""
    __tablename__ = "snapshot_phishkits"

    snapshot_id = Column(String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), primary_key=True)
    phishkit_id = Column(String(36), ForeignKey("phishkits.id", ondelete="CASCADE"), primary_key=True)
    similarity = Column(Float, default=1.0)


# ===========================================================================
# Phase 3 — Campaign models
# ===========================================================================

class CampaignModel(Base):
    """A coordinated phishing campaign targeting a brand or sector."""
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(200), nullable=False, unique=True)
    target_brand = Column(String(100), nullable=True)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)
    domain_count = Column(Integer, default=0)
    kit_signature = Column(Text, nullable=True)
    status = Column(String(20), default="active")  # active, dormant, closed
    meta = Column(JSON, default=dict)

    clusters = relationship("CampaignClusterModel", back_populates="campaign", lazy="dynamic")


class CampaignClusterModel(Base):
    """Association between a campaign and its constituent clusters."""
    __tablename__ = "campaign_clusters"

    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True)
    cluster_id = Column(String(36), ForeignKey("clusters.id", ondelete="CASCADE"), primary_key=True)

    campaign = relationship("CampaignModel", back_populates="clusters")
    cluster = relationship("ClusterModel")


# ===========================================================================
# Phase 4 — Actor models
# ===========================================================================

class ActorModel(Base):
    """A threat actor profile built from campaign and infrastructure signals."""
    __tablename__ = "actors"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    label = Column(String(200), nullable=False, unique=True)
    fingerprint = Column(JSON, nullable=False)
    confidence_score = Column(Float, default=0.0)
    first_seen = Column(DateTime, default=utc_now, nullable=False)
    last_seen = Column(DateTime, default=utc_now, nullable=False)
    meta = Column(JSON, default=dict)

    campaigns = relationship("ActorCampaignModel", back_populates="actor", lazy="dynamic")


class ActorCampaignModel(Base):
    """Association between an actor and their campaigns."""
    __tablename__ = "actor_campaigns"

    actor_id = Column(String(36), ForeignKey("actors.id", ondelete="CASCADE"), primary_key=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), primary_key=True)

    actor = relationship("ActorModel", back_populates="campaigns")
    campaign = relationship("CampaignModel")


class C2CandidateModel(Base):
    """A C2 candidate identified by the intelligence pipeline."""
    __tablename__ = "c2_candidates"
    __table_args__ = (
        UniqueConstraint("ioc_id", "snapshot_id", name="uq_c2_candidate_snapshot"),
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    ioc_id = Column(Integer, ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False)
    snapshot_id = Column(String(36), ForeignKey("snapshots.id", ondelete="CASCADE"), nullable=True)
    c2_score = Column(Float, nullable=False)
    signals = Column(JSON, default=list)
    detected_at = Column(DateTime, default=utc_now, nullable=False)

    ioc = relationship("IocModel")


# ---------------------------------------------------------------------------
# Engine & Session helpers
# ---------------------------------------------------------------------------

def get_engine():
    """Create a SQLAlchemy engine from config.DATABASE_URL.

    For SQLite we enable check_same_thread=False so the engine works
    across threads in FastAPI.  For in-memory SQLite we additionally
    use a StaticPool so the same connection is shared across threads.
    """
    db_url = config.DATABASE_URL
    is_sqlite = db_url.startswith("sqlite")
    is_memory = db_url == "sqlite:///:memory:"

    kwargs: dict = {}
    kwargs["pool_pre_ping"] = True
    if is_sqlite:
        kwargs["connect_args"] = {"check_same_thread": False}
    if is_memory:
        kwargs["poolclass"] = StaticPool

    return create_engine(db_url, **kwargs)


_SessionFactory = sessionmaker(expire_on_commit=False, class_=Session)

# Module-level cache so we don't re-create the engine on every call.
_engine = None


def get_session():
    """Return a new SQLAlchemy session bound to the default engine."""
    global _engine
    if _engine is None:
        _engine = get_engine()
    return _SessionFactory(bind=_engine)


def get_db():
    """FastAPI dependency that guarantees session cleanup per request."""
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def init_db(engine=None):
    """Create all tables that do not yet exist.

    In production, schema migrations should be managed exclusively through
    Alembic (``alembic upgrade head``).  Calling ``create_all()`` in prod
    risks diverging the Alembic version table from the actual schema state,
    which would make future migrations unreliable.  We therefore skip
    ``create_all()`` when ENVIRONMENT == "production" and log a warning
    instead.  In development (the default), ``create_all()`` is preserved
    for convenience so that a fresh ``python main.py`` bootstraps the
    database automatically.
    """
    import logging
    _log = logging.getLogger(__name__)

    if config.ENVIRONMENT == "production":
        _log.warning(
            "init_db() called in production — skipping create_all(). "
            "Use Alembic (alembic upgrade head) to manage schema migrations."
        )
        return

    if engine is None:
        engine = get_engine()
    Base.metadata.create_all(bind=engine)


def check_required_tables(required_tables: list[str], engine=None) -> tuple[bool, list[str]]:
    """Return whether *required_tables* exist, plus any missing table names."""
    if engine is None:
        engine = get_engine()
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    missing = [name for name in required_tables if name not in existing]
    return (len(missing) == 0, missing)


def verify_production_schema(engine=None) -> None:
    """Fail fast when production database schema is not migration-ready."""
    if engine is None:
        engine = get_engine()

    # Core tables needed for API startup + plugin seeding.
    required = [
        "alembic_version",
        "groups",
        "domains",
        "snapshots",
        "plugin_weights",
    ]
    ok, missing = check_required_tables(required, engine=engine)
    if not ok:
        raise RuntimeError(
            "Production DB schema is not ready. Missing tables: "
            + ", ".join(sorted(missing))
            + ". Run `alembic upgrade head` before starting the API."
        )

    # Ensure alembic_version has at least one row.
    with engine.connect() as conn:
        row = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).fetchone()
        if row is None or not row[0]:
            raise RuntimeError(
                "Production DB schema is not migration-tracked "
                "(alembic_version is empty). Run `alembic upgrade head`."
            )


def reset_db(engine=None):
    """Drop all tables and recreate them. Destructive — use with caution."""
    if engine is None:
        engine = get_engine()
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


