"""C2 ranking service for VigilWolf v2.

Scans IOC records for command-and-control indicators and scores each IOC
on its likelihood of being a C2 endpoint.  Produces a ranked list of
candidates useful for analyst triage and downstream alerting.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Optional

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


def _is_phishkit_linked(ioc_id: int, session) -> bool:
    """Check if an IOC occurs in a snapshot linked to a phishkit.

    Joins IocOccurrenceModel -> SnapshotModel -> SnapshotPhishkitModel to
    determine whether any snapshot containing this IOC also has a phishkit
    association.
    """
    from database import (  # type: ignore[import-untyped]
        IocOccurrenceModel,
        SnapshotPhishkitModel,
    )

    occ_rows = (
        session.query(IocOccurrenceModel.snapshot_id)
        .filter(IocOccurrenceModel.ioc_id == ioc_id)
        .all()
    )
    snapshot_ids = [row.snapshot_id for row in occ_rows]
    if not snapshot_ids:
        return False

    phishkit_link = (
        session.query(SnapshotPhishkitModel)
        .filter(SnapshotPhishkitModel.snapshot_id.in_(snapshot_ids))
        .first()
    )
    return phishkit_link is not None


def _domain_count_for_ioc(ioc_id: int, session) -> int:
    """Count the number of distinct domains an IOC appears across.

    Joins IocOccurrenceModel -> SnapshotModel -> DomainModel to count
    unique domains.
    """
    from database import (  # type: ignore[import-untyped]
        DomainModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    rows = (
        session.query(DomainModel.id)
        .join(SnapshotModel, SnapshotModel.domain_id == DomainModel.id)
        .join(IocOccurrenceModel, IocOccurrenceModel.snapshot_id == SnapshotModel.id)
        .filter(IocOccurrenceModel.ioc_id == ioc_id)
        .distinct()
        .all()
    )
    return len(rows)


def _receives_post_data(ioc_id: int, session) -> bool:
    """Check if an IOC is classified as an exfiltration endpoint.

    An IOC with role='exfil_endpoint' in any occurrence is considered to
    receive POST data (this is how the IOC service labels form action URLs
    that exfiltrate credentials).
    """
    from database import IocOccurrenceModel  # type: ignore[import-untyped]

    exfil = (
        session.query(IocOccurrenceModel)
        .filter(
            IocOccurrenceModel.ioc_id == ioc_id,
            IocOccurrenceModel.role == "exfil_endpoint",
        )
        .first()
    )
    return exfil is not None


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
    from database import (  # type: ignore[import-untyped]
        AnalysisResultModel,
        IocModel,
        IocOccurrenceModel,
    )

    # Fetch all IOCs that are URLs or domains (most likely C2 vectors).
    iocs = (
        session.query(IocModel)
        .filter(IocModel.type.in_(["url", "domain", "ip"]))
        .order_by(IocModel.id)
        .all()
    )

    if not iocs:
        logger.info("rank_c2_candidates: no IOCs found, returning empty list.")
        return []

    candidates: list[dict] = []

    for ioc in iocs:
        score = 0.0
        signals: list[str] = []

        # Signal 1: POST/form target URL
        if _is_post_form_target(ioc.value, ioc.type):
            score += SCORE_POST_FORM_TARGET
            signals.append("post_form_target")

        # Signal 2: Used in 5+ domains
        domain_count = _domain_count_for_ioc(ioc.id, session)
        if domain_count >= MULTI_DOMAIN_THRESHOLD:
            score += SCORE_MULTI_DOMAIN
            signals.append(f"multi_domain:{domain_count}")

        # Signal 3: Linked to phishkit
        if _is_phishkit_linked(ioc.id, session):
            score += SCORE_LINKED_PHISHKIT
            signals.append("phishkit_linked")

        # Signal 4: Receives POST data (exfil_endpoint role)
        if _receives_post_data(ioc.id, session):
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