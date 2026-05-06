"""Clustering service for VigilWolf v2.

Groups domains into clusters based on HTML structural similarity and
shared infrastructure signals.  Produces ClusterModel / ClusterMemberModel
rows that downstream services (campaign detection, actor profiling) consume.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

CLUSTERING_WINDOW_DAYS = 30

# Watermark keys for incremental processing
_WATERMARK_STRUCTURAL_HASH = "structural_hash"
_WATERMARK_INFRASTRUCTURE = "infrastructure"

# Common ASNs that host massive shared infrastructure and should not be used
# for infra clustering (they create false mega-clusters).
_COMMON_ASN_DENYLIST = frozenset({
    "AS13335",  # Cloudflare
    "AS20940",  # Akamai
    "AS16509",  # AWS
    "AS14618",  # AWS
    "AS15169",  # Google
    "AS8075",   # Microsoft
    "AS13414",  # Twitter
})

# Maximum number of domains in a single cluster — larger groups are skipped
# to prevent false mega-clusters from shared infrastructure.
MAX_CLUSTER_SIZE = 500


# ---------------------------------------------------------------------------
# Watermark helpers
# ---------------------------------------------------------------------------


def _read_watermark(session, key: str) -> Optional[datetime]:
    """Read the watermark for a clustering key. Returns None if no watermark exists."""
    from database import ClusteringWatermarkModel  # type: ignore[import-untyped]

    row = session.query(ClusteringWatermarkModel).filter(
        ClusteringWatermarkModel.id == key
    ).first()
    if row is not None:
        return row.last_processed_at.replace(tzinfo=timezone.utc) if row.last_processed_at.tzinfo is None else row.last_processed_at
    return None


def _write_watermark(session, key: str, timestamp: datetime) -> None:
    """Write or update the watermark for a clustering key.

    Uses session.merge() to atomically insert-or-update, eliminating the
    race condition where concurrent workers could both query-for-absence and
    then both try to insert.
    """
    from database import ClusteringWatermarkModel  # type: ignore[import-untyped]

    now = datetime.now(timezone.utc)
    row = ClusteringWatermarkModel(
        id=key,
        last_processed_at=timestamp,
        updated_at=now,
    )
    session.merge(row)
    session.flush()


# ---------------------------------------------------------------------------
# Structural-hash clustering
# ---------------------------------------------------------------------------

def cluster_by_structural_hash(session) -> dict:
    """Cluster domains that share the same HTML structural hash.

    Queries all html_hasher analysis results, groups by structural_hash,
    and creates ClusterModel + ClusterMemberModel rows for groups of 2+
    domains sharing the same hash.

    Uses watermark-based incremental processing: on subsequent runs, only
    snapshots newer than the watermark are processed. Falls back to full-scan
    if no watermark exists (first run or after reset).

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with clusters_created and domains_clustered counts.
    """
    from database import (  # type: ignore[import-untyped]
        AnalysisResultModel,
        ClusterMemberModel,
        ClusterModel,
        SnapshotModel,
    )

    # Only consider recent snapshots to avoid re-scanning the entire history.
    clustering_cutoff = datetime.now(timezone.utc) - timedelta(days=CLUSTERING_WINDOW_DAYS)

    # Watermark: if set, only process snapshots newer than the watermark.
    watermark = _read_watermark(session, _WATERMARK_STRUCTURAL_HASH)
    effective_cutoff = max(clustering_cutoff, watermark) if watermark else clustering_cutoff
    if watermark:
        logger.info(
            "Structural-hash clustering: watermark=%s, effective_cutoff=%s",
            watermark.isoformat(), effective_cutoff.isoformat(),
        )

    recent_snapshot_ids = {
        row.id
        for row in session.query(SnapshotModel)
        .filter(SnapshotModel.timestamp >= effective_cutoff)
        .all()
    }

    results = (
        session.query(AnalysisResultModel)
        .filter(
            AnalysisResultModel.plugin_name == "html_hasher",
            AnalysisResultModel.snapshot_id.in_(recent_snapshot_ids),
        )
        .all()
    )

    # Group domain_ids by structural_hash.
    hash_groups: dict[str, set[str]] = defaultdict(set)
    for result in results:
        findings = result.result_json or {}
        structural_hash = findings.get("structural_hash")
        if not structural_hash:
            continue

        # Resolve the domain_id through the snapshot.
        snapshot = session.query(SnapshotModel).get(result.snapshot_id)
        if snapshot is None:
            continue
        domain_id = snapshot.domain_id

        # Deduplication is automatic with sets.
        hash_groups[structural_hash].add(domain_id)

    clusters_created = 0
    domains_clustered = 0

    for structural_hash, domain_ids in hash_groups.items():
        if len(domain_ids) < 3:
            continue

        # Find or create the cluster.
        cluster = (
            session.query(ClusterModel)
            .filter(
                ClusterModel.cluster_type == "html_similarity",
                ClusterModel.signature_hash == structural_hash,
                ClusterModel.signature_type == "structural_hash",
            )
            .first()
        )

        if cluster is None:
            try:
                with session.begin_nested():
                    cluster = ClusterModel(
                        id=str(uuid.uuid4()),
                        cluster_type="html_similarity",
                        signature_hash=structural_hash,
                        signature_type="structural_hash",
                        description=f"HTML structural similarity cluster ({structural_hash[:12]}...)",
                        domain_count=0,
                    )
                    session.add(cluster)
                    session.flush()
                clusters_created += 1
            except Exception:
                # Concurrent insert — look up the cluster that was just created
                cluster = (
                    session.query(ClusterModel)
                    .filter(
                        ClusterModel.cluster_type == "html_similarity",
                        ClusterModel.signature_hash == structural_hash,
                        ClusterModel.signature_type == "structural_hash",
                    )
                    .first()
                )
                if cluster is None:
                    logger.error("Cluster lookup failed after IntegrityError for hash %s", structural_hash[:12])
                    continue

        # Add member domains (skip if already a member).
        added = 0
        for domain_id in domain_ids:
            try:
                with session.begin_nested():
                    exists = (
                        session.query(ClusterMemberModel)
                        .filter(
                            ClusterMemberModel.cluster_id == cluster.id,
                            ClusterMemberModel.domain_id == domain_id,
                        )
                        .first()
                    )
                    if exists:
                        continue
                    member = ClusterMemberModel(
                        cluster_id=cluster.id,
                        domain_id=domain_id,
                        confidence=1.0,  # exact structural match
                    )
                    session.add(member)
                    session.flush()
                added += 1
            except Exception:
                logger.debug(
                    "Cluster member already exists: cluster=%s domain=%s",
                    cluster.id[:8], domain_id[:8],
                )

        # Update cluster metadata with atomic domain_count.
        if added:
            from sqlalchemy import func as sa_func, update as sa_update
            actual_count = (
                session.query(sa_func.count(ClusterMemberModel.id))
                .filter(ClusterMemberModel.cluster_id == cluster.id)
                .scalar()
            ) or 0
            session.execute(
                sa_update(ClusterModel)
                .where(ClusterModel.id == cluster.id)
                .values(
                    domain_count=actual_count,
                    last_seen=datetime.now(timezone.utc),
                )
            )
            session.refresh(cluster, ["domain_count", "last_seen"])
            domains_clustered += added
            logger.debug(
                "Cluster %s: added %d domains (total %d)",
                cluster.id, added, cluster.domain_count,
            )

    session.flush()

    # Write watermark after successful processing.
    _write_watermark(session, _WATERMARK_STRUCTURAL_HASH, datetime.now(timezone.utc))

    logger.info(
        "Structural-hash clustering: %d clusters created, %d domains clustered",
        clusters_created, domains_clustered,
    )
    return {"clusters_created": clusters_created, "domains_clustered": domains_clustered}


# ---------------------------------------------------------------------------
# Infrastructure clustering
# ---------------------------------------------------------------------------

def _build_infra_signature(domain_id: str, domain_map: dict, ip_map: dict, ns_map: dict) -> Optional[str]:
    """Build an infrastructure signature tuple for a domain.

    The signature is (asn, registrar, first NS record).  Returns None if
    the domain has no IP records (cannot determine ASN).

    Uses pre-loaded domain_map, ip_map, and ns_map instead of per-domain
    DB queries for bulk efficiency.
    """
    domain = domain_map.get(domain_id)
    if domain is None:
        return None

    # ASN: take from the first IP record (by first_seen) that has one.
    asn = None
    domain_ips = ip_map.get(domain_id, [])
    if domain_ips:
        sorted_ips = sorted(
            domain_ips,
            key=lambda ip: ip.first_seen or datetime.min.replace(tzinfo=timezone.utc),
        )
        for ip_record in sorted_ips:
            if hasattr(ip_record, "asn") and ip_record.asn:
                asn = str(ip_record.asn)
                # Null out common ASNs that create false mega-clusters.
                if asn in _COMMON_ASN_DENYLIST:
                    asn = None
                break

    # Registrar: stored on DomainProcessingState or domain meta.
    # Fallback: check if DomainModel has registrar attribute.
    registrar = getattr(domain, "registrar", None)

    # First NS record (by first_seen).
    first_ns = None
    domain_ns = ns_map.get(domain_id, [])
    if domain_ns:
        sorted_ns = sorted(
            domain_ns,
            key=lambda ns: ns.first_seen or datetime.min.replace(tzinfo=timezone.utc),
        )
        first_ns = sorted_ns[0].value

    # Build signature. Require at least 2 of 3 signal fields to avoid grouping
    # unrelated domains that happen to share a blank field.
    signal_count = sum(1 for v in (asn, registrar, first_ns) if v is not None)
    if signal_count < 2:
        return None

    # Penalize common registrars that create false clusters — domains sharing
    # only a popular registrar are unlikely to be related.
    _COMMON_REGISTRARS = {
        "namecheap", "godaddy", "register.com", "enom", "tucows",
        "network solutions", "123-reg", "key-systems", "pdr ltd.",
    }
    if registrar and registrar.lower().strip() in _COMMON_REGISTRARS and signal_count < 3:
        # A common registrar alone (without ASN and NS also matching) is
        # insufficient to link domains — downgrade to None so it doesn't
        # contribute to the signature hash.
        registrar = None
        signal_count -= 1
        if signal_count < 2:
            return None

    return f"{asn or '_'}|{registrar or '_'}|{first_ns or '_'}"


def cluster_by_infrastructure(session) -> dict:
    """Cluster domains that share the same infrastructure signature.

    Infrastructure signature = (asn, registrar, first NS record).
    Domains with identical signatures are grouped into an infra cluster.

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with clusters_created and domains_clustered counts.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        ClusterModel,
        DnsRecordModel,
        DomainIpModel,
        DomainModel,
        SnapshotModel,
    )

    # Only consider domains that have been seen recently.
    clustering_cutoff = datetime.now(timezone.utc) - timedelta(days=CLUSTERING_WINDOW_DAYS)

    # Watermark: if set, only process snapshots newer than the watermark.
    watermark = _read_watermark(session, _WATERMARK_INFRASTRUCTURE)
    effective_cutoff = max(clustering_cutoff, watermark) if watermark else clustering_cutoff
    if watermark:
        logger.info(
            "Infrastructure clustering: watermark=%s, effective_cutoff=%s",
            watermark.isoformat(), effective_cutoff.isoformat(),
        )

    recent_domain_ids = {
        row.domain_id
        for row in session.query(SnapshotModel)
        .filter(SnapshotModel.timestamp >= effective_cutoff)
        .all()
    }

    # Bulk-preload domain data for infra signatures (S-2)
    domain_map: dict = {d.id: d for d in session.query(DomainModel).filter(
        DomainModel.id.in_(recent_domain_ids)
    ).all()} if recent_domain_ids else {}
    ip_map: dict[str, list] = defaultdict(list)
    for ip in session.query(DomainIpModel).filter(
        DomainIpModel.domain_id.in_(recent_domain_ids)
    ).all() if recent_domain_ids else []:
        ip_map[ip.domain_id].append(ip)
    ns_map: dict[str, list] = defaultdict(list)
    for ns in session.query(DnsRecordModel).filter(
        DnsRecordModel.domain_id.in_(recent_domain_ids),
        DnsRecordModel.type == "NS",
    ).all() if recent_domain_ids else []:
        ns_map[ns.domain_id].append(ns)

    sig_groups: dict[str, list[str]] = defaultdict(list)

    for domain_id in domain_map:
        sig = _build_infra_signature(domain_id, domain_map, ip_map, ns_map)
        if sig is None:
            continue
        sig_groups[sig].append(domain_id)

    clusters_created = 0
    domains_clustered = 0

    for sig, domain_ids in sig_groups.items():
        if len(domain_ids) < 3:
            continue

        # Skip mega-clusters from shared infrastructure.
        if len(domain_ids) > MAX_CLUSTER_SIZE:
            logger.debug(
                "Skipping infra cluster with %d domains (exceeds MAX_CLUSTER_SIZE=%d): sig=%s",
                len(domain_ids), MAX_CLUSTER_SIZE, sig[:40],
            )
            continue

        # Derive a stable hash from the signature string.
        sig_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()

        # Find or create the cluster.
        cluster = (
            session.query(ClusterModel)
            .filter(
                ClusterModel.cluster_type == "infra",
                ClusterModel.signature_hash == sig_hash,
                ClusterModel.signature_type == "infra_signature",
            )
            .first()
        )

        if cluster is None:
            try:
                with session.begin_nested():
                    cluster = ClusterModel(
                        id=str(uuid.uuid4()),
                        cluster_type="infra",
                        signature_hash=sig_hash,
                        signature_type="infra_signature",
                        description=f"Infrastructure cluster (ASN/registrar/NS: {sig})",
                        domain_count=0,
                        meta={"raw_signature": sig},
                    )
                    session.add(cluster)
                    session.flush()
                clusters_created += 1
            except Exception:
                # Concurrent insert — look up the cluster that was just created
                cluster = (
                    session.query(ClusterModel)
                    .filter(
                        ClusterModel.cluster_type == "infra",
                        ClusterModel.signature_hash == sig_hash,
                        ClusterModel.signature_type == "infra_signature",
                    )
                    .first()
                )
                if cluster is None:
                    logger.error("Cluster lookup failed after IntegrityError for infra hash %s", sig_hash[:12])
                    continue

        # Add member domains.
        added = 0
        for domain_id in domain_ids:
            try:
                with session.begin_nested():
                    exists = (
                        session.query(ClusterMemberModel)
                        .filter(
                            ClusterMemberModel.cluster_id == cluster.id,
                            ClusterMemberModel.domain_id == domain_id,
                        )
                        .first()
                    )
                    if exists:
                        continue
                    member = ClusterMemberModel(
                        cluster_id=cluster.id,
                        domain_id=domain_id,
                        confidence=0.8,  # infra match is softer than structural hash
                    )
                    session.add(member)
                    session.flush()
                added += 1
            except Exception:
                logger.debug(
                    "Cluster member already exists: cluster=%s domain=%s",
                    cluster.id[:8], domain_id[:8],
                )

        if added:
            from sqlalchemy import func as sa_func, update as sa_update
            actual_count = (
                session.query(sa_func.count(ClusterMemberModel.id))
                .filter(ClusterMemberModel.cluster_id == cluster.id)
                .scalar()
            ) or 0
            session.execute(
                sa_update(ClusterModel)
                .where(ClusterModel.id == cluster.id)
                .values(
                    domain_count=actual_count,
                    last_seen=datetime.now(timezone.utc),
                )
            )
            session.refresh(cluster, ["domain_count", "last_seen"])
            domains_clustered += added
            logger.debug(
                "Infra cluster %s: added %d domains (total %d)",
                cluster.id, added, cluster.domain_count,
            )

    session.flush()

    # Write watermark after successful processing.
    _write_watermark(session, _WATERMARK_INFRASTRUCTURE, datetime.now(timezone.utc))

    logger.info(
        "Infrastructure clustering: %d clusters created, %d domains clustered",
        clusters_created, domains_clustered,
    )
    return {"clusters_created": clusters_created, "domains_clustered": domains_clustered}


# ---------------------------------------------------------------------------
# Reconciliation
# ---------------------------------------------------------------------------


def reconcile_cluster_domain_counts(session) -> dict:
    """Reconcile ClusterModel.domain_count with actual ClusterMemberModel rows.

    Uses a single GROUP BY query to count actual members per cluster, then
    updates only the clusters where domain_count has drifted.  This corrects
    drift caused by race conditions or failed transactions during clustering.

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with clusters_checked and clusters_updated counts.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        ClusterModel,
    )
    from sqlalchemy import func

    # Single GROUP BY query instead of N+1 per-cluster queries
    actual_counts = dict(
        session.query(
            ClusterMemberModel.cluster_id,
            func.count(ClusterMemberModel.id).label("count"),
        )
        .group_by(ClusterMemberModel.cluster_id)
        .all()
    )

    clusters = session.query(ClusterModel).all()

    clusters_checked = 0
    clusters_updated = 0

    for cluster in clusters:
        clusters_checked += 1
        actual_count = actual_counts.get(cluster.id, 0)

        if cluster.domain_count != actual_count:
            logger.info(
                "Reconciling cluster %s: domain_count %d -> %d",
                cluster.id[:8], cluster.domain_count, actual_count,
            )
            cluster.domain_count = actual_count
            clusters_updated += 1

    session.flush()
    logger.info(
        "Cluster domain_count reconciliation: %d checked, %d updated",
        clusters_checked, clusters_updated,
    )
    return {"clusters_checked": clusters_checked, "clusters_updated": clusters_updated}


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------

def get_clusters_for_domain(domain_id: str, session) -> list[dict]:
    """Return all clusters that contain the given domain.

    Args:
        domain_id: UUID of the domain.
        session: SQLAlchemy session.

    Returns:
        List of dicts with cluster id, type, signature, description,
        confidence, and joined_at.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        ClusterModel,
    )

    rows = (
        session.query(ClusterModel, ClusterMemberModel)
        .join(ClusterMemberModel, ClusterModel.id == ClusterMemberModel.cluster_id)
        .filter(ClusterMemberModel.domain_id == domain_id)
        .all()
    )

    return [
        {
            "cluster_id": cluster.id,
            "cluster_type": cluster.cluster_type,
            "signature_hash": cluster.signature_hash,
            "signature_type": cluster.signature_type,
            "description": cluster.description,
            "domain_count": cluster.domain_count,
            "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
            "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
            "confidence": member.confidence,
            "joined_at": member.joined_at.isoformat() if member.joined_at else None,
        }
        for cluster, member in rows
    ]


# ---------------------------------------------------------------------------
# Snapshot-level entry point
# ---------------------------------------------------------------------------


def cluster_snapshot(snapshot_id: str) -> int:
    """Run clustering triggered by a specific snapshot.

    Opens a DB session, verifies the snapshot exists, runs both structural
    hash and infrastructure clustering, and returns the total number of
    clusters created or updated.  Exceptions are caught and logged so the
    caller never has to handle them.

    Args:
        snapshot_id: UUID of the snapshot that triggered this pipeline run.

    Returns:
        Total number of clusters created/updated (0 if nothing happened or
        an error occurred).
    """
    try:
        from database import AnalysisResultModel, SnapshotModel, get_session  # type: ignore[import-untyped]

        with get_session() as session:
            # Verify the snapshot exists.
            snapshot = session.query(SnapshotModel).get(snapshot_id)
            if snapshot is None:
                logger.warning(
                    "cluster_snapshot: snapshot %s not found; skipping.",
                    snapshot_id,
                )
                return 0

            # Run both clustering passes.
            structural = cluster_by_structural_hash(session)
            infra = cluster_by_infrastructure(session)
            session.commit()

        total = (
            structural.get("clusters_created", 0)
            + infra.get("clusters_created", 0)
        )
        logger.info(
            "cluster_snapshot(%s): %d clusters created/updated",
            snapshot_id, total,
        )
        return total
    except Exception:
        logger.exception(
            "cluster_snapshot failed for snapshot_id=%s", snapshot_id,
        )
        return 0


def get_cluster_details(cluster_id: str, session) -> Optional[dict]:
    """Return full cluster details including all member domains.

    Args:
        cluster_id: UUID of the cluster.
        session: SQLAlchemy session.

    Returns:
        Dict with cluster info and member list, or None if not found.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        ClusterModel,
        DomainModel,
    )

    cluster = session.query(ClusterModel).get(cluster_id)
    if cluster is None:
        return None

    members = (
        session.query(ClusterMemberModel, DomainModel)
        .join(DomainModel, ClusterMemberModel.domain_id == DomainModel.id)
        .filter(ClusterMemberModel.cluster_id == cluster_id)
        .all()
    )

    return {
        "id": cluster.id,
        "cluster_type": cluster.cluster_type,
        "signature_hash": cluster.signature_hash,
        "signature_type": cluster.signature_type,
        "description": cluster.description,
        "domain_count": cluster.domain_count,
        "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
        "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
        "meta": cluster.meta or {},
        "members": [
            {
                "domain_id": domain.id,
                "url": domain.url,
                "confidence": member.confidence,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
            }
            for member, domain in members
        ],
    }