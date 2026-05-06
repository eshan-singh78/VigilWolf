"""PhishKit detection service for VigilWolf v2.

Identifies phishing kits by correlating structural hashes from the html_hasher
plugin across snapshots.  When two or more snapshots share the same
structural_hash they are grouped into a PhishkitModel, linked via
SnapshotPhishkitModel rows, and a phishkit-type ClusterModel is created so
downstream campaign/actor services can consume the grouping.

Exfiltration endpoints are enriched from ioc_extractor plugin results when
available.
"""
from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

PHISHKIT_WINDOW_DAYS = 30

# Benign shared-infrastructure domains that should never be set as exfil_endpoint.
_PHISHKIT_BENIGN_DOMAIN_DENYLIST = frozenset({
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.com", "hotjar.com", "mixpanel.com", "segment.com",
    "cloudflare.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
    "stripe.com", "paypal.com", "js.stripe.com",
    "recaptcha.net", "www.google.com", "www.googletagmanager.com",
})


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def detect_phishkits(session) -> dict:
    """Detect phishing kits by analysing JS hash overlap from html_hasher results.

    Algorithm:
      1. Query every AnalysisResultModel row where plugin_name == "html_hasher".
      2. Extract the structural_hash from each result's findings JSON.
      3. Group snapshot_ids by structural_hash.
      4. For each group with 2+ snapshots:
         - Create or update a PhishkitModel keyed on signature_hash.
         - Link every snapshot in the group via SnapshotPhishkitModel.
         - Enrich exfil_endpoint from ioc_extractor results where available.
         - Create a phishkit-type ClusterModel and add member domains.

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with phishkits_created, phishkits_updated, snapshots_linked counts.
    """
    from database import (  # type: ignore[import-untyped]
        AnalysisResultModel,
        ClusterMemberModel,
        ClusterModel,
        DomainModel,
        PhishkitModel,
        SnapshotModel,
        SnapshotPhishkitModel,
    )

    # -- Step 1: collect recent html_hasher results ------------------------------
    phishkit_cutoff = datetime.now(timezone.utc) - timedelta(days=PHISHKIT_WINDOW_DAYS)

    # Use yield_per for batched loading and filter by timestamp via join
    # instead of loading all snapshot IDs into memory.
    results = (
        session.query(AnalysisResultModel)
        .join(SnapshotModel, AnalysisResultModel.snapshot_id == SnapshotModel.id)
        .filter(
            AnalysisResultModel.plugin_name == "html_hasher",
            SnapshotModel.timestamp >= phishkit_cutoff,
        )
        .yield_per(500)
        .all()
    )

    # -- Step 2: group snapshot_ids by structural_hash --------------------------
    hash_to_snapshots: dict[str, list[str]] = defaultdict(list)
    for result in results:
        findings = result.result_json or {}
        structural_hash = findings.get("structural_hash")
        if not structural_hash:
            continue
        # Avoid recording the same snapshot twice for the same hash.
        if result.snapshot_id not in hash_to_snapshots[structural_hash]:
            hash_to_snapshots[structural_hash].append(result.snapshot_id)

    phishkits_created = 0
    phishkits_updated = 0
    snapshots_linked = 0

    # Pre-load all ioc_extractor results for the relevant snapshots (P1-6).
    # This avoids N+1 per-snapshot queries in _enrich_exfil_endpoint.
    all_snapshot_ids_in_results = {r.snapshot_id for r in results}
    ioc_results_map: dict[str, dict] = {}
    if all_snapshot_ids_in_results:
        ioc_rows = (
            session.query(AnalysisResultModel)
            .filter(
                AnalysisResultModel.plugin_name == "ioc_extractor",
                AnalysisResultModel.snapshot_id.in_(all_snapshot_ids_in_results),
            )
            .all()
        )
        for row in ioc_rows:
            ioc_results_map[row.snapshot_id] = row.result_json or {}

    # -- Step 3: process each group ---------------------------------------------
    for structural_hash, snapshot_ids in hash_to_snapshots.items():
        if len(snapshot_ids) < 3:
            continue

        # Resolve domain_ids for all snapshots in this group (needed later for
        # cluster membership and exfil enrichment).
        snapshot_domain_map: dict[str, str] = {}
        for sid in snapshot_ids:
            snap = session.query(SnapshotModel).get(sid)
            if snap is not None:
                snapshot_domain_map[sid] = snap.domain_id

        # -- Find or create PhishkitModel --------------------------------------
        phishkit = (
            session.query(PhishkitModel)
            .filter(PhishkitModel.signature_hash == structural_hash)
            .first()
        )

        if phishkit is None:
            try:
                with session.begin_nested():
                    phishkit = PhishkitModel(
                        id=str(uuid.uuid4()),
                        signature_hash=structural_hash,
                        meta={},
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                    )
                    session.add(phishkit)
                    session.flush()
                phishkits_created += 1
                logger.debug("Created phishkit %s (hash=%s)", phishkit.id, structural_hash[:12])
            except Exception:
                # Concurrent insert — look up the phishkit that was just created
                phishkit = (
                    session.query(PhishkitModel)
                    .filter(PhishkitModel.signature_hash == structural_hash)
                    .first()
                )
                if phishkit is None:
                    logger.error("Phishkit lookup failed after IntegrityError for hash %s", structural_hash[:12])
                    continue
                # Defer last_seen update until we know whether new links were added.
        else:
            # Defer last_seen update and counter increment until we know
            # whether any new links were actually created (see below).
            pass

        # -- Link snapshots via SnapshotPhishkitModel --------------------------
        new_link_count = 0
        for sid in snapshot_ids:
            try:
                with session.begin_nested():
                    existing_link = (
                        session.query(SnapshotPhishkitModel)
                        .filter(
                            SnapshotPhishkitModel.snapshot_id == sid,
                            SnapshotPhishkitModel.phishkit_id == phishkit.id,
                        )
                        .first()
                    )
                    if existing_link is not None:
                        continue
                    link = SnapshotPhishkitModel(
                        snapshot_id=sid,
                        phishkit_id=phishkit.id,
                        similarity=1.0,  # exact structural hash match
                    )
                    session.add(link)
                    session.flush()
                new_link_count += 1
            except Exception:
                logger.debug(
                    "Snapshot-phishkit link already exists: snapshot=%s phishkit=%s",
                    sid[:8], phishkit.id[:8],
                )

        snapshots_linked += new_link_count

        # Only update last_seen and count as "updated" when new data was added.
        if new_link_count > 0:
            phishkit.last_seen = datetime.now(timezone.utc)
            phishkits_updated += 1

        # -- Enrich exfil_endpoint from ioc_extractor --------------------------
        if phishkit.exfil_endpoint is None:
            _enrich_exfil_endpoint(phishkit, snapshot_ids, session, ioc_results_map)

        # -- Create / update phishkit-type ClusterModel ------------------------
        _upsert_phishkit_cluster(structural_hash, snapshot_domain_map, session)

    session.flush()

    logger.info(
        "detect_phishkits: %d created, %d updated, %d snapshots linked",
        phishkits_created, phishkits_updated, snapshots_linked,
    )
    return {
        "phishkits_created": phishkits_created,
        "phishkits_updated": phishkits_updated,
        "snapshots_linked": snapshots_linked,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_benign_domain(url_or_hostname: str) -> bool:
    """Check if a URL or hostname belongs to a benign shared-infrastructure domain.

    Returns True if the hostname matches or is a subdomain of a known benign domain.
    """
    # Try parsing as a URL first; fall back to treating the string as a hostname.
    hostname = urlparse(url_or_hostname).hostname
    if not hostname:
        hostname = url_or_hostname
    hostname = hostname.lower()
    return any(hostname == d or hostname.endswith(f".{d}") for d in _PHISHKIT_BENIGN_DOMAIN_DENYLIST)


def _enrich_exfil_endpoint(phishkit, snapshot_ids: list[str], session, ioc_results_map: dict[str, dict] | None = None) -> None:
    """Look for exfiltration endpoint IOCs in ioc_extractor results.

    Pre-loads all exfil_endpoint IOCs for the snapshot set in a single query,
    then checks each snapshot.  Benign shared-infrastructure domains are
    skipped to avoid false enrichment.  Accepts a pre-loaded ioc_results_map
    to avoid N+1 per-snapshot queries.
    """
    from database import (  # type: ignore[import-untyped]
        IocModel,
        IocOccurrenceModel,
    )

    # Pre-load all exfil_endpoint IOCs for these snapshots in one query
    exfil_rows = (
        session.query(IocOccurrenceModel.snapshot_id, IocModel.value)
        .join(IocModel, IocOccurrenceModel.ioc_id == IocModel.id)
        .filter(
            IocOccurrenceModel.snapshot_id.in_(snapshot_ids),
            IocOccurrenceModel.role == "exfil_endpoint",
            IocModel.type == "url",
        )
        .all()
    )
    # Map snapshot_id -> list of exfil endpoint values
    exfil_by_snapshot: dict[str, list[str]] = {}
    for row in exfil_rows:
        exfil_by_snapshot.setdefault(row.snapshot_id, []).append(row.value)

    for sid in snapshot_ids:
        # Check pre-loaded exfil_endpoint IOCs first
        exfil_values = exfil_by_snapshot.get(sid, [])
        for value in exfil_values:
            if _is_benign_domain(value):
                logger.debug(
                    "Skipping benign exfil_endpoint=%s for phishkit %s (snapshot %s)",
                    value, phishkit.id, sid,
                )
                continue
            phishkit.exfil_endpoint = value
            logger.debug(
                "Enriched phishkit %s exfil_endpoint=%s from snapshot %s",
                phishkit.id, value, sid,
            )
            return

        # Fallback: inspect pre-loaded ioc_extractor findings JSON for form action URLs.
        findings = (ioc_results_map or {}).get(sid)
        if findings is None:
            continue

        urls = findings.get("urls", [])
        for url in urls:
            url_lower = url.lower()
            if any(sig in url_lower for sig in ("submit", "login", "api/login", "api/submit")):
                # Skip benign shared-infrastructure domains.
                if _is_benign_domain(url):
                    logger.debug(
                        "Skipping benign heuristic exfil_endpoint=%s for phishkit %s (snapshot %s)",
                        url, phishkit.id, sid,
                    )
                    continue
                phishkit.exfil_endpoint = url
                logger.debug(
                    "Enriched phishkit %s exfil_endpoint=%s (heuristic) from snapshot %s",
                    phishkit.id, url, sid,
                )
                return


def _upsert_phishkit_cluster(
    structural_hash: str,
    snapshot_domain_map: dict[str, str],
    session,
) -> None:
    """Create or update a ClusterModel of type 'phishkit' for the grouping.

    Ensures every domain represented in snapshot_domain_map is a member of the
    cluster.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        ClusterModel,
    )

    cluster = (
        session.query(ClusterModel)
        .filter(
            ClusterModel.cluster_type == "phishkit",
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
                    cluster_type="phishkit",
                    signature_hash=structural_hash,
                    signature_type="structural_hash",
                    description=f"Phishkit cluster (structural_hash {structural_hash[:12]}...)",
                    domain_count=0,
                )
                session.add(cluster)
                session.flush()
            logger.debug("Created phishkit cluster %s", cluster.id)
        except Exception:
            # Concurrent insert — look up the cluster that was just created
            cluster = (
                session.query(ClusterModel)
                .filter(
                    ClusterModel.cluster_type == "phishkit",
                    ClusterModel.signature_hash == structural_hash,
                    ClusterModel.signature_type == "structural_hash",
                )
                .first()
            )
            if cluster is None:
                logger.error("Cluster lookup failed after IntegrityError for phishkit hash %s", structural_hash[:12])
                return

    # Collect unique domain_ids from the snapshot-domain mapping.
    domain_ids = list(set(snapshot_domain_map.values()))

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
                if exists is not None:
                    continue
                member = ClusterMemberModel(
                    cluster_id=cluster.id,
                    domain_id=domain_id,
                    confidence=1.0,  # exact structural hash match
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
        session.refresh(cluster, ["domain_count", "last_seen"])


# ---------------------------------------------------------------------------
# Snapshot-level entry point
# ---------------------------------------------------------------------------


def detect_phishkits_for_snapshot(snapshot_id: str) -> int:
    """Run phishkit detection triggered by a specific snapshot.

    Opens a DB session, verifies the snapshot exists and has html_hasher
    analysis results, runs phishkit detection, and returns the total number
    of phishkits created or updated.  Exceptions are caught and logged so
    the caller never has to handle them.

    Args:
        snapshot_id: UUID of the snapshot that triggered this pipeline run.

    Returns:
        Total number of phishkits created/updated (0 if nothing happened or
        an error occurred).
    """
    try:
        from database import (  # type: ignore[import-untyped]
            AnalysisResultModel,
            SnapshotModel,
            get_session,
        )

        with get_session() as session:
            # Verify the snapshot exists.
            snapshot = session.query(SnapshotModel).get(snapshot_id)
            if snapshot is None:
                logger.warning(
                    "detect_phishkits_for_snapshot: snapshot %s not found; skipping.",
                    snapshot_id,
                )
                return 0

            # Check for html_hasher results for this snapshot.
            has_results = (
                session.query(AnalysisResultModel)
                .filter(
                    AnalysisResultModel.snapshot_id == snapshot_id,
                    AnalysisResultModel.plugin_name == "html_hasher",
                )
                .first()
            )
            if has_results is None:
                logger.debug(
                    "detect_phishkits_for_snapshot: no html_hasher results for "
                    "snapshot %s; skipping.",
                    snapshot_id,
                )
                return 0

            # Run phishkit detection across all qualifying snapshots.
            result = detect_phishkits(session)
            session.commit()

        total = result.get("phishkits_created", 0) + result.get("phishkits_updated", 0)
        logger.info(
            "detect_phishkits_for_snapshot(%s): %d phishkits created/updated",
            snapshot_id, total,
        )
        return total
    except Exception:
        logger.exception(
            "detect_phishkits_for_snapshot failed for snapshot_id=%s", snapshot_id,
        )
        return 0


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------


def get_phishkits(session, limit: int = 50) -> list[dict]:
    """List recent phishkits sorted by last_seen descending.

    Args:
        session: SQLAlchemy session.
        limit: Maximum number of results to return.

    Returns:
        List of dicts with phishkit id, signature_hash, panel_path,
        exfil_endpoint, meta, first_seen, last_seen.
    """
    from database import PhishkitModel  # type: ignore[import-untyped]

    rows = (
        session.query(PhishkitModel)
        .order_by(PhishkitModel.last_seen.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "id": pk.id,
            "signature_hash": pk.signature_hash,
            "panel_path": pk.panel_path,
            "exfil_endpoint": pk.exfil_endpoint,
            "meta": pk.meta or {},
            "first_seen": pk.first_seen.isoformat() if pk.first_seen else None,
            "last_seen": pk.last_seen.isoformat() if pk.last_seen else None,
        }
        for pk in rows
    ]


def get_phishkit_details(phishkit_id: str, session) -> Optional[dict]:
    """Return a phishkit with all linked snapshots and associated domains.

    Args:
        phishkit_id: UUID of the PhishkitModel.
        session: SQLAlchemy session.

    Returns:
        Dict with phishkit info, linked snapshots (with domain details),
        or None if the phishkit does not exist.
    """
    from database import (  # type: ignore[import-untyped]
        DomainModel,
        PhishkitModel,
        SnapshotModel,
        SnapshotPhishkitModel,
    )

    phishkit = session.query(PhishkitModel).get(phishkit_id)
    if phishkit is None:
        return None

    # Fetch all snapshot-phishkit links for this phishkit.
    links = (
        session.query(SnapshotPhishkitModel, SnapshotModel, DomainModel)
        .join(
            SnapshotModel,
            SnapshotPhishkitModel.snapshot_id == SnapshotModel.id,
        )
        .join(
            DomainModel,
            SnapshotModel.domain_id == DomainModel.id,
        )
        .filter(SnapshotPhishkitModel.phishkit_id == phishkit_id)
        .order_by(SnapshotModel.timestamp.desc())
        .all()
    )

    snapshots = []
    seen_domain_ids: set[str] = set()

    for link, snapshot, domain in links:
        snapshots.append({
            "snapshot_id": snapshot.id,
            "timestamp": snapshot.timestamp.isoformat() if snapshot.timestamp else None,
            "trigger_type": snapshot.trigger_type,
            "similarity": link.similarity,
            "domain_id": domain.id,
            "domain_url": domain.url,
        })
        seen_domain_ids.add(domain.id)

    return {
        "id": phishkit.id,
        "signature_hash": phishkit.signature_hash,
        "panel_path": phishkit.panel_path,
        "exfil_endpoint": phishkit.exfil_endpoint,
        "meta": phishkit.meta or {},
        "first_seen": phishkit.first_seen.isoformat() if phishkit.first_seen else None,
        "last_seen": phishkit.last_seen.isoformat() if phishkit.last_seen else None,
        "snapshot_count": len(snapshots),
        "domain_count": len(seen_domain_ids),
        "snapshots": snapshots,
    }