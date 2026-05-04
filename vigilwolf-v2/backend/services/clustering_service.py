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

# Watermark IDs corresponding to each clustering pass.
WATERMARK_STRUCTURAL_HASH = "structural_hash"
WATERMARK_INFRA = "infra"


def _get_watermark(watermark_id: str, session) -> Optional[datetime]:
    """Read the last-processed timestamp for a clustering pass.

    Returns None if no watermark exists (first run).
    """
    from database import ClusteringWatermarkModel  # type: ignore[import-untyped]
    row = session.query(ClusteringWatermarkModel).get(watermark_id)
    if row is None:
        return None
    return row.last_processed_at


def _set_watermark(watermark_id: str, timestamp: datetime, session) -> None:
    """Upsert the watermark for a clustering pass.

    Uses max() to ensure the watermark only advances forward,
    preventing concurrent passes from going backwards.
    """
    from database import ClusteringWatermarkModel  # type: ignore[import-untyped]
    row = session.query(ClusteringWatermarkModel).get(watermark_id)
    if row is not None:
        # Only advance the watermark forward (C-3 race condition fix)
        row.last_processed_at = max(row.last_processed_at, timestamp) if row.last_processed_at else timestamp
        row.updated_at = datetime.now(timezone.utc)
    else:
        session.add(ClusteringWatermarkModel(
            id=watermark_id,
            last_processed_at=timestamp,
            updated_at=datetime.now(timezone.utc),
        ))
    session.flush()


# ---------------------------------------------------------------------------
# Structural-hash clustering
# ---------------------------------------------------------------------------

def cluster_by_structural_hash(session) -> dict:
    """Cluster domains that share the same HTML structural hash.

    Uses an incremental watermark: only processes snapshots newer than the
    last run, avoiding re-scanning the entire 30-day window each time.

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

    # Incremental: only process snapshots since the last clustering run.
    watermark = _get_watermark(WATERMARK_STRUCTURAL_HASH, session)
    query_start = watermark if watermark and watermark > clustering_cutoff else clustering_cutoff

    snapshot_rows = (
        session.query(SnapshotModel.id, SnapshotModel.domain_id, SnapshotModel.timestamp)
        .filter(SnapshotModel.timestamp >= query_start)
        .all()
    )

    if not snapshot_rows:
        logger.debug("No new snapshots since watermark for structural_hash clustering; skipping.")
        return {"clusters_created": 0, "domains_clustered": 0}

    max_timestamp = max(ts for _, _, ts in snapshot_rows)

    # Build snapshot->domain mapping from already-loaded data (no extra query).
    snap_domain_map = {row_id: domain_id for row_id, domain_id, _ in snapshot_rows}

    # Use JOIN instead of IN clause to avoid PostgreSQL parameter limits at scale.
    results = (
        session.query(AnalysisResultModel)
        .join(SnapshotModel, AnalysisResultModel.snapshot_id == SnapshotModel.id)
        .filter(
            AnalysisResultModel.plugin_name == "html_hasher",
            SnapshotModel.timestamp >= query_start,
        )
        .all()
    )

    # Group domain_ids by structural_hash.
    hash_groups: dict[str, list[str]] = defaultdict(list)
    for result in results:
        findings = result.result_json or {}
        structural_hash = findings.get("structural_hash")
        if not structural_hash:
            continue

        domain_id = snap_domain_map.get(result.snapshot_id)
        if domain_id is None:
            continue

        # Avoid duplicate domain entries within the same hash group.
        if domain_id not in hash_groups[structural_hash]:
            hash_groups[structural_hash].append(domain_id)

    clusters_created = 0
    domains_clustered = 0

    for structural_hash, domain_ids in hash_groups.items():
        # Check if a cluster already exists for this hash before applying
        # the minimum-count threshold — new domains should always be added
        # to an existing cluster, even if there are fewer than 3 in this
        # watermark window.
        existing_cluster = (
            session.query(ClusterModel)
            .filter(
                ClusterModel.cluster_type == "html_similarity",
                ClusterModel.signature_hash == structural_hash,
                ClusterModel.signature_type == "structural_hash",
            )
            .first()
        )

        if existing_cluster is None and len(domain_ids) < 3:
            continue

        # Find or create the cluster.
        cluster = existing_cluster

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

        # Update cluster metadata.
        if added:
            from sqlalchemy import update as sa_update
            session.execute(
                sa_update(ClusterModel)
                .where(ClusterModel.id == cluster.id)
                .values(
                    domain_count=ClusterModel.domain_count + added,
                    last_seen=datetime.now(timezone.utc),
                )
            )
            domains_clustered += added
            logger.debug(
                "Cluster %s: added %d domains (total %d)",
                cluster.id, added, cluster.domain_count,
            )

    session.flush()

    # Always advance the watermark when snapshots were processed, even if no
    # new clusters were created. This prevents reprocessing the same batch
    # indefinitely when all domains are already clustered.
    _set_watermark(WATERMARK_STRUCTURAL_HASH, max_timestamp, session)

    logger.info(
        "Structural-hash clustering: %d clusters created, %d domains clustered",
        clusters_created, domains_clustered,
    )
    return {"clusters_created": clusters_created, "domains_clustered": domains_clustered}


# ---------------------------------------------------------------------------
# Infrastructure clustering
# ---------------------------------------------------------------------------

def _build_infra_signature(
    domain_id: str,
    asn: Optional[str],
    registrar: Optional[str],
    first_ns: Optional[str],
) -> Optional[str]:
    """Build an infrastructure signature from pre-loaded data.

    Takes ASN, registrar, and first NS record instead of querying per-domain.
    Returns None if fewer than 2 of 3 signal fields are present, or if the
    only overlap is a common registrar.
    """
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

    Uses an incremental watermark: only processes snapshots newer than the
    last run, avoiding re-scanning the entire 30-day window each time.

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

    # Incremental: only process snapshots since the last clustering run.
    watermark = _get_watermark(WATERMARK_INFRA, session)
    query_start = watermark if watermark and watermark > clustering_cutoff else clustering_cutoff

    snapshot_rows = (
        session.query(SnapshotModel.domain_id, SnapshotModel.timestamp)
        .filter(SnapshotModel.timestamp >= query_start)
        .all()
    )

    if not snapshot_rows:
        logger.debug("No new snapshots since watermark for infra clustering; skipping.")
        return {"clusters_created": 0, "domains_clustered": 0}

    recent_domain_ids = {row_domain_id for row_domain_id, _ in snapshot_rows}
    max_timestamp = max(ts for _, ts in snapshot_rows)

    # Use JOIN-based subquery instead of IN clause for domain filtering.
    domains = (
        session.query(DomainModel)
        .join(SnapshotModel, DomainModel.id == SnapshotModel.domain_id)
        .filter(SnapshotModel.timestamp >= query_start)
        .distinct()
        .all()
    )

    # Batch-load ASN data: use the LATEST IP record with ASN per domain
    # (not the first — domains that moved from CDN to phishing hosts should
    # use the current ASN, not the CDN ASN, for accurate clustering)
    # NOTE: IN clause is acceptable here because recent_domain_ids contains
    # domain IDs (typically 10K-50K), not snapshot IDs (which can reach 300K+).
    # Revisit with a JOIN if domain volume grows significantly.
    domain_first_asn: dict[str, str | None] = {}
    if recent_domain_ids:
        ip_records = (
            session.query(DomainIpModel)
            .filter(DomainIpModel.domain_id.in_(recent_domain_ids))
            .order_by(DomainIpModel.first_seen.desc())
            .all()
        )
        for ip in ip_records:
            if ip.domain_id not in domain_first_asn and hasattr(ip, "asn") and ip.asn:
                domain_first_asn[ip.domain_id] = str(ip.asn)

    # Batch-load first NS record per domain
    # NOTE: IN clause is acceptable here (see ASN comment above for scale rationale).
    domain_first_ns: dict[str, str | None] = {}
    if recent_domain_ids:
        ns_records = (
            session.query(DnsRecordModel)
            .filter(
                DnsRecordModel.domain_id.in_(recent_domain_ids),
                DnsRecordModel.type == "NS",
            )
            .order_by(DnsRecordModel.first_seen)
            .all()
        )
        for ns in ns_records:
            if ns.domain_id not in domain_first_ns:
                domain_first_ns[ns.domain_id] = ns.value

    # Pre-load registrar from domain objects
    domain_registrar_map: dict[str, str | None] = {}
    for domain in domains:
        domain_registrar_map[domain.id] = getattr(domain, "registrar", None)

    sig_groups: dict[str, list[str]] = defaultdict(list)

    for domain in domains:
        sig = _build_infra_signature(
            domain.id,
            asn=domain_first_asn.get(domain.id),
            registrar=domain_registrar_map.get(domain.id),
            first_ns=domain_first_ns.get(domain.id),
        )
        if sig is None:
            continue
        sig_groups[sig].append(domain.id)

    clusters_created = 0
    domains_clustered = 0

    for sig, domain_ids in sig_groups.items():
        # Derive a stable hash from the signature string.
        sig_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()

        # Check if a cluster already exists before applying the minimum-count
        # threshold — new domains should always be added to existing clusters.
        existing_cluster = (
            session.query(ClusterModel)
            .filter(
                ClusterModel.cluster_type == "infra",
                ClusterModel.signature_hash == sig_hash,
                ClusterModel.signature_type == "infra_signature",
            )
            .first()
        )

        if existing_cluster is None and len(domain_ids) < 3:
            continue

        # Find or create the cluster.
        cluster = existing_cluster

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
            from sqlalchemy import update as sa_update
            session.execute(
                sa_update(ClusterModel)
                .where(ClusterModel.id == cluster.id)
                .values(
                    domain_count=ClusterModel.domain_count + added,
                    last_seen=datetime.now(timezone.utc),
                )
            )
            domains_clustered += added
            logger.debug(
                "Infra cluster %s: added %d domains (total %d)",
                cluster.id, added, cluster.domain_count,
            )

    session.flush()

    # Always advance the watermark when snapshots were processed, even if no
    # new clusters were created. This prevents reprocessing the same batch
    # indefinitely when all domains are already clustered.
    _set_watermark(WATERMARK_INFRA, max_timestamp, session)

    logger.info(
        "Infrastructure clustering: %d clusters created, %d domains clustered",
        clusters_created, domains_clustered,
    )
    return {"clusters_created": clusters_created, "domains_clustered": domains_clustered}


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