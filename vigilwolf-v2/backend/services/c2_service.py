"""C2 ranking service for VigilWolf v2.

Scans IOC records for command-and-control indicators and scores each IOC
on its likelihood of being a C2 endpoint.  Produces a ranked list of
candidates useful for analyst triage and downstream alerting.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring weights for C2 indicators
# ---------------------------------------------------------------------------
SCORE_POST_FORM_TARGET = 0.3
SCORE_MULTI_DOMAIN = 0.2
SCORE_LINKED_PHISHKIT = 0.2
SCORE_RECEIVES_POST = 0.2

# Multi-domain threshold: IOC appears in snapshots across this many distinct
# domains before it qualifies for the multi-domain signal.
MULTI_DOMAIN_THRESHOLD = 5

# Maximum number of candidates to return.
MAX_CANDIDATES = 50

# Only consider IOCs seen within this many days for C2 ranking.
C2_WINDOW_DAYS = 30

# Maximum number of IOC candidates to load for C2 ranking.
# Caps memory usage at scale by prioritizing most-recently-seen IOCs.
MAX_C2_IOC_CANDIDATES = 5000


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------


def _is_post_form_target(ioc_value: str, ioc_type: str) -> bool:
    """Check if a URL IOC looks like a POST/form submission target.

    Matches common phishing exfiltration URL patterns (login, submit, post,
    api endpoints, form handlers).
    """
    if ioc_type != "url":
        return False
    lower = ioc_value.lower()
    indicators = (
        "post", "submit", "login", "form", "upload", "send",
        "api/login", "api/submit", "process", "verify", "check",
        "action", "capture", "collect", "exfil",
    )
    return any(sig in lower for sig in indicators)


# ---------------------------------------------------------------------------
# Bulk signal pre-loading helpers
# ---------------------------------------------------------------------------


def _bulk_preload_signals(ioc_ids: list[int], session) -> tuple[dict[int, int], set[int], dict[int, str]]:
    """Bulk-pre-load C2 signals for all IOCs at once.

    Returns three structures that replace the old per-IOC queries:
      - ioc_domain_count: maps ioc_id -> count of distinct domains
      - ioc_has_phishkit: set of ioc_ids linked to phishkit snapshots
      - ioc_roles: maps ioc_id -> its role (from IocOccurrenceModel)
    """
    from database import (  # type: ignore[import-untyped]
        DomainModel,
        IocOccurrenceModel,
        SnapshotModel,
        SnapshotPhishkitModel,
    )
    from sqlalchemy import func as sa_func

    # 1. Domain counts per IOC: join occurrences -> snapshots -> domains, count distinct domains
    domain_count_rows = (
        session.query(
            IocOccurrenceModel.ioc_id,
            sa_func.count(sa_func.distinct(SnapshotModel.domain_id)),
        )
        .join(SnapshotModel, SnapshotModel.id == IocOccurrenceModel.snapshot_id)
        .filter(IocOccurrenceModel.ioc_id.in_(ioc_ids))
        .group_by(IocOccurrenceModel.ioc_id)
        .all()
    )
    ioc_domain_count: dict[int, int] = {row[0]: row[1] for row in domain_count_rows}

    # 2. Phishkit linkage: find all snapshot_ids linked to phishkits, then find which ioc_ids
    #    appear in those snapshots.
    # First, get all snapshot_ids that contain any of our IOCs.
    occ_snapshot_rows = (
        session.query(
            IocOccurrenceModel.ioc_id,
            IocOccurrenceModel.snapshot_id,
        )
        .filter(IocOccurrenceModel.ioc_id.in_(ioc_ids))
        .all()
    )
    # Map snapshot_id -> set of ioc_ids for fast lookup
    snapshot_to_ioc_ids: dict[str, set[int]] = defaultdict(set)
    all_snapshot_ids: set[str] = set()
    for row in occ_snapshot_rows:
        snapshot_to_ioc_ids[row.snapshot_id].add(row.ioc_id)
        all_snapshot_ids.add(row.snapshot_id)

    # Find which of those snapshots are linked to phishkits.
    phishkit_snapshots = (
        session.query(SnapshotPhishkitModel.snapshot_id)
        .filter(SnapshotPhishkitModel.snapshot_id.in_(all_snapshot_ids))
        .all()
    )
    phishkit_snapshot_ids = {row.snapshot_id for row in phishkit_snapshots}

    ioc_has_phishkit: set[int] = set()
    for snap_id in phishkit_snapshot_ids:
        ioc_has_phishkit.update(snapshot_to_ioc_ids.get(snap_id, set()))

    # 3. IOC roles: get the role from IocOccurrenceModel for each ioc_id.
    #    If an IOC has multiple occurrences with different roles, prefer
    #    'exfil_endpoint' over others (it is the strongest C2 signal).
    role_rows = (
        session.query(
            IocOccurrenceModel.ioc_id,
            IocOccurrenceModel.role,
        )
        .filter(IocOccurrenceModel.ioc_id.in_(ioc_ids))
        .all()
    )
    ioc_roles: dict[int, str] = {}
    for row in role_rows:
        ioc_id = row.ioc_id
        role = row.role or "resource"
        existing = ioc_roles.get(ioc_id)
        if existing is None or role == "exfil_endpoint":
            # Prefer exfil_endpoint; otherwise keep whatever we saw first.
            ioc_roles[ioc_id] = role

    return ioc_domain_count, ioc_has_phishkit, ioc_roles


# ---------------------------------------------------------------------------
# Core service function
# ---------------------------------------------------------------------------


def rank_c2_candidates(session) -> list[dict]:
    """Scan IOCs for C2 indicators and return a ranked list of candidates.

    Each IOC is scored across four signals:

    1. POST/form target URL (+0.3): The IOC value matches patterns consistent
       with credential-exfiltration endpoints.
    2. Used in 5+ domains (+0.2): The IOC appears across many distinct domains,
       suggesting infrastructure reuse typical of C2.
    3. Linked to phishkit (+0.2): The IOC co-occurs with a detected phishkit,
       increasing confidence that it is part of an attack chain.
    4. Receives POST data (+0.2): The IOC has been classified as an
       exfil_endpoint by the IOC role classifier.

    Returns the top 50 candidates sorted by c2_score descending.

    Args:
        session: SQLAlchemy session (read-only query is sufficient).

    Returns:
        List of dicts, each with ioc_id, ioc_type, ioc_value, c2_score,
        and signals list.
    """
    from database import IocModel  # type: ignore[import-untyped]

    # Fetch IOCs that are URLs or domains (most likely C2 vectors),
    # limited to those seen within the C2 time window.
    cutoff = datetime.now(timezone.utc) - timedelta(days=C2_WINDOW_DAYS)
    iocs = (
        session.query(IocModel)
        .filter(
            IocModel.type.in_(["url", "domain", "ip"]),
            IocModel.last_seen >= cutoff,
        )
        .order_by(IocModel.last_seen.desc())  # most recent first
        .limit(MAX_C2_IOC_CANDIDATES)
        .all()
    )

    if not iocs:
        logger.info("rank_c2_candidates: no IOCs found, returning empty list.")
        return []

    # Bulk pre-load all C2 signals in 3 queries instead of 3 per IOC.
    ioc_ids = [ioc.id for ioc in iocs]
    ioc_domain_count, ioc_has_phishkit, ioc_roles = _bulk_preload_signals(ioc_ids, session)

    candidates: list[dict] = []

    for ioc in iocs:
        score = 0.0
        signals: list[str] = []

        # Signal 1: POST/form target URL
        if _is_post_form_target(ioc.value, ioc.type):
            score += SCORE_POST_FORM_TARGET
            signals.append("post_form_target")

        # Signal 2: Used in 5+ domains (from bulk pre-load)
        domain_count = ioc_domain_count.get(ioc.id, 0)
        if domain_count >= MULTI_DOMAIN_THRESHOLD:
            score += SCORE_MULTI_DOMAIN
            signals.append(f"multi_domain:{domain_count}")

        # Signal 3: Linked to phishkit (from bulk pre-load)
        if ioc.id in ioc_has_phishkit:
            score += SCORE_LINKED_PHISHKIT
            signals.append("phishkit_linked")

        # Signal 4: Receives POST data / exfil_endpoint role (from bulk pre-load)
        if ioc_roles.get(ioc.id) == "exfil_endpoint":
            score += SCORE_RECEIVES_POST
            signals.append("receives_post_data")

        # Only include IOCs with at least one signal.
        if score > 0.0:
            candidates.append({
                "ioc_id": ioc.id,
                "ioc_type": ioc.type,
                "ioc_value": ioc.value,
                "c2_score": round(score, 4),
                "signals": signals,
            })

    # Sort by c2_score descending, break ties by ioc_id for determinism.
    candidates.sort(key=lambda c: (-c["c2_score"], c["ioc_id"]))

    # Cap at MAX_CANDIDATES.
    candidates = candidates[:MAX_CANDIDATES]

    logger.info(
        "rank_c2_candidates: %d candidates identified (top score: %.3f)",
        len(candidates),
        candidates[0]["c2_score"] if candidates else 0.0,
    )
    return candidates