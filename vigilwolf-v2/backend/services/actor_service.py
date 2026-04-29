"""Actor profiling service for VigilWolf v2.

Builds threat actor profiles by comparing campaigns across four signal
dimensions: shared phishkit signatures, shared infrastructure, shared IOCs,
and temporal overlap.  Produces ActorModel and ActorCampaignModel rows that
link campaigns believed to be operated by the same actor.
"""
from __future__ import annotations

import hashlib
import itertools
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal-dimension weights
# ---------------------------------------------------------------------------
WEIGHT_SHARED_KIT = 0.3
WEIGHT_SHARED_INFRA = 0.3
WEIGHT_SHARED_IOCS = 0.2
WEIGHT_TEMPORAL = 0.2

# Confidence thresholds
CONFIDENCE_THRESHOLD = 0.5
LIKELY_SAME_THRESHOLD = 0.8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _jaccard(set_a: set, set_b: set) -> float:
    """Compute Jaccard similarity between two sets.

    Returns 0.0 if both sets are empty (no signal to compare).
    """
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


def _temporal_overlap(
    first_seen_a: Optional[datetime],
    last_seen_a: Optional[datetime],
    first_seen_b: Optional[datetime],
    last_seen_b: Optional[datetime],
) -> float:
    """Compute temporal overlap as a 0-1 score.

    If either campaign is missing timestamps, returns 0.  The overlap is the
    ratio of the intersection duration to the union duration.  When both
    campaigns are instantaneous (identical timestamps), returns 1.0 if they
    coincide, 0.0 otherwise.
    """
    if any(v is None for v in (first_seen_a, last_seen_a, first_seen_b, last_seen_b)):
        return 0.0

    # Ensure timezone-aware comparison
    def _aware(dt: datetime) -> datetime:
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt

    a_start, a_end = _aware(first_seen_a), _aware(last_seen_a)  # type: ignore[arg-type]
    b_start, b_end = _aware(first_seen_b), _aware(last_seen_b)  # type: ignore[arg-type]

    overlap_start = max(a_start, b_start)
    overlap_end = min(a_end, b_end)

    if overlap_start > overlap_end:
        return 0.0

    overlap_duration = (overlap_end - overlap_start).total_seconds()
    union_start = min(a_start, b_start)
    union_end = max(a_end, b_end)
    union_duration = (union_end - union_start).total_seconds()

    if union_duration == 0:
        # Both campaigns are instantaneous at the same moment.
        return 1.0

    return min(1.0, overlap_duration / union_duration)


def _compute_shared_kit(camp_a, camp_b, session) -> float:
    """Compute shared phishkit similarity between two campaigns.

    Compares kit_signature fields; returns 1.0 if they match, 0.0 otherwise.
    Campaigns without a kit_signature contribute 0.0.
    """
    sig_a = camp_a.kit_signature
    sig_b = camp_b.kit_signature
    if not sig_a or not sig_b:
        return 0.0
    return 1.0 if sig_a == sig_b else 0.0


def _compute_shared_infra(camp_a, camp_b, session) -> float:
    """Compute shared infrastructure similarity between two campaigns.

    Compares the sets of infra-cluster IDs associated with each campaign
    via CampaignClusterModel and uses Jaccard similarity.
    """
    from database import CampaignClusterModel  # type: ignore[import-untyped]

    clusters_a = {
        row.cluster_id
        for row in session.query(CampaignClusterModel)
        .filter(CampaignClusterModel.campaign_id == camp_a.id)
        .all()
    }
    clusters_b = {
        row.cluster_id
        for row in session.query(CampaignClusterModel)
        .filter(CampaignClusterModel.campaign_id == camp_b.id)
        .all()
    }

    # Filter to infra clusters only
    from database import ClusterModel  # type: ignore[import-untyped]

    if clusters_a:
        infra_a = {
            cid
            for cid in clusters_a
            if session.query(ClusterModel).get(cid) is not None
            and session.query(ClusterModel).get(cid).cluster_type == "infra"
        }
    else:
        infra_a = set()

    if clusters_b:
        infra_b = {
            cid
            for cid in clusters_b
            if session.query(ClusterModel).get(cid) is not None
            and session.query(ClusterModel).get(cid).cluster_type == "infra"
        }
    else:
        infra_b = set()

    return _jaccard(infra_a, infra_b)


def _compute_shared_iocs(camp_a, camp_b, session) -> float:
    """Compute shared IOC similarity between two campaigns.

    Gathers IOC IDs from all domains belonging to each campaign and computes
    Jaccard similarity.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        CampaignClusterModel,
        DomainModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    def _campaign_ioc_ids(campaign_id: str) -> set[int]:
        """Resolve all IOC IDs for a campaign through its clusters and domains."""
        cluster_ids = {
            row.cluster_id
            for row in session.query(CampaignClusterModel)
            .filter(CampaignClusterModel.campaign_id == campaign_id)
            .all()
        }
        if not cluster_ids:
            return set()

        domain_ids = {
            row.domain_id
            for row in session.query(ClusterMemberModel)
            .filter(ClusterMemberModel.cluster_id.in_(cluster_ids))
            .all()
        }
        if not domain_ids:
            return set()

        snapshot_ids = {
            row.id
            for row in session.query(SnapshotModel)
            .filter(SnapshotModel.domain_id.in_(domain_ids))
            .all()
        }
        if not snapshot_ids:
            return set()

        return {
            row.ioc_id
            for row in session.query(IocOccurrenceModel)
            .filter(IocOccurrenceModel.snapshot_id.in_(snapshot_ids))
            .all()
        }

    iocs_a = _campaign_ioc_ids(camp_a.id)
    iocs_b = _campaign_ioc_ids(camp_b.id)
    return _jaccard(iocs_a, iocs_b)


def _build_fingerprint(
    camp_a,
    camp_b,
    shared_kit: float,
    shared_infra: float,
    shared_iocs: float,
    temporal: float,
    session,
) -> dict:
    """Build the actor fingerprint JSON blob.

    Aggregates shared signals and derives preferred registrar, ASN, exfil
    channels, and target brands from the linked campaigns and their clusters.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignClusterModel,
        ClusterMemberModel,
        ClusterModel,
        DomainIpModel,
        DnsRecordModel,
        DomainModel,
        IocModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    fingerprint: dict = {
        "shared_signals": {
            "shared_kit": round(shared_kit, 4),
            "shared_infra": round(shared_infra, 4),
            "shared_iocs": round(shared_iocs, 4),
            "temporal_overlap": round(temporal, 4),
        },
        "preferred_registrar": None,
        "preferred_asn": None,
        "exfil_channels": [],
        "target_brands": [],
    }

    # Collect all cluster IDs across both campaigns.
    campaign_ids = [camp_a.id, camp_b.id]
    cluster_ids: set[str] = set()
    for cid in campaign_ids:
        rows = (
            session.query(CampaignClusterModel)
            .filter(CampaignClusterModel.campaign_id == cid)
            .all()
        )
        cluster_ids.update(r.cluster_id for r in rows)

    # Domain IDs from all clusters.
    domain_ids: set[str] = set()
    for cluster_id in cluster_ids:
        members = (
            session.query(ClusterMemberModel)
            .filter(ClusterMemberModel.cluster_id == cluster_id)
            .all()
        )
        domain_ids.update(m.domain_id for m in members)

    # Preferred registrar: most frequent registrar among domain IPs.
    registrar_counts: dict[str, int] = defaultdict(int)
    asn_counts: dict[str, int] = defaultdict(int)
    for did in domain_ids:
        domain = session.query(DomainModel).get(did)
        if domain is None:
            continue
        registrar = getattr(domain, "registrar", None)
        if registrar:
            registrar_counts[registrar] += 1
        ip_row = (
            session.query(DomainIpModel)
            .filter(DomainIpModel.domain_id == did)
            .order_by(DomainIpModel.first_seen)
            .first()
        )
        if ip_row and hasattr(ip_row, "asn") and ip_row.asn:
            asn_counts[str(ip_row.asn)] += 1

    if registrar_counts:
        fingerprint["preferred_registrar"] = max(
            registrar_counts, key=registrar_counts.get  # type: ignore[arg-type]
        )
    if asn_counts:
        fingerprint["preferred_asn"] = max(
            asn_counts, key=asn_counts.get  # type: ignore[arg-type]
        )

    # Exfil channels: IOC values with role=exfil_endpoint across campaign domains.
    snapshot_ids = {
        s.id
        for s in session.query(SnapshotModel)
        .filter(SnapshotModel.domain_id.in_(domain_ids))
        .all()
    }
    if snapshot_ids:
        exfil_iocs = (
            session.query(IocModel)
            .join(IocOccurrenceModel, IocModel.id == IocOccurrenceModel.ioc_id)
            .filter(
                IocOccurrenceModel.snapshot_id.in_(snapshot_ids),
                IocOccurrenceModel.role == "exfil_endpoint",
            )
            .distinct()
            .all()
        )
        fingerprint["exfil_channels"] = list(
            {ioc.value for ioc in exfil_iocs}
        )[:20]  # cap at 20

    # Target brands: combine from both campaigns.
    target_brands: set[str] = set()
    if camp_a.target_brand:
        target_brands.add(camp_a.target_brand)
    if camp_b.target_brand:
        target_brands.add(camp_b.target_brand)
    fingerprint["target_brands"] = sorted(target_brands)

    return fingerprint


def _generate_label(confidence: float, fingerprint: dict) -> str:
    """Generate a deterministic actor label from confidence and fingerprint.

    >0.8: LIKELY_SAME_{hash8}
    0.5-0.8: POSSIBLE_{hash8}
    """
    shared = fingerprint.get("shared_signals", {})
    raw = (
        f"{shared.get('shared_kit', 0)}"
        f"{shared.get('shared_infra', 0)}"
        f"{shared.get('shared_iocs', 0)}"
        f"{shared.get('temporal_overlap', 0)}"
    )
    tag = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:8]

    if confidence > LIKELY_SAME_THRESHOLD:
        return f"LIKELY_SAME_{tag}"
    return f"POSSIBLE_{tag}"


# ---------------------------------------------------------------------------
# Core service functions
# ---------------------------------------------------------------------------


def profile_actors(session) -> dict:
    """Profile threat actors by comparing every pair of campaigns.

    For each campaign pair, calculates a confidence score as a weighted sum
    of four signal dimensions:

        confidence = (shared_kit * 0.3) + (shared_infra * 0.3)
                   + (shared_iocs * 0.2) + (temporal_overlap * 0.2)

    If confidence > 0.5, an ActorModel is created (or updated) linking both
    campaigns via ActorCampaignModel rows.  The actor label is derived from
    the confidence level and a deterministic hash of the shared signals.

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with actors_created and actors_updated counts.
    """
    from database import (  # type: ignore[import-untyped]
        ActorCampaignModel,
        ActorModel,
        CampaignModel,
    )

    campaigns = session.query(CampaignModel).all()
    if len(campaigns) < 2:
        logger.info("profile_actors: fewer than 2 campaigns, nothing to profile.")
        return {"actors_created": 0, "actors_updated": 0}

    actors_created = 0
    actors_updated = 0

    # Compare every unique pair of campaigns.
    for camp_a, camp_b in itertools.combinations(campaigns, 2):
        shared_kit = _compute_shared_kit(camp_a, camp_b, session)
        shared_infra = _compute_shared_infra(camp_a, camp_b, session)
        shared_iocs = _compute_shared_iocs(camp_a, camp_b, session)
        temporal = _temporal_overlap(
            camp_a.first_seen, camp_a.last_seen,
            camp_b.first_seen, camp_b.last_seen,
        )

        confidence = (
            shared_kit * WEIGHT_SHARED_KIT
            + shared_infra * WEIGHT_SHARED_INFRA
            + shared_iocs * WEIGHT_SHARED_IOCS
            + temporal * WEIGHT_TEMPORAL
        )

        if confidence <= CONFIDENCE_THRESHOLD:
            logger.debug(
                "Campaign pair %s/%s: confidence=%.3f (below threshold)",
                camp_a.id[:8], camp_b.id[:8], confidence,
            )
            continue

        # Build fingerprint before finding/creating actor.
        fingerprint = _build_fingerprint(
            camp_a, camp_b, shared_kit, shared_infra, shared_iocs, temporal, session,
        )
        label = _generate_label(confidence, fingerprint)

        # Check if an actor already links these two campaigns.
        existing = (
            session.query(ActorModel)
            .join(ActorCampaignModel, ActorModel.id == ActorCampaignModel.actor_id)
            .filter(ActorCampaignModel.campaign_id == camp_a.id)
            .all()
        )
        existing_actor = None
        for actor in existing:
            # Does this actor also link camp_b?
            link = (
                session.query(ActorCampaignModel)
                .filter(
                    ActorCampaignModel.actor_id == actor.id,
                    ActorCampaignModel.campaign_id == camp_b.id,
                )
                .first()
            )
            if link is not None:
                existing_actor = actor
                break

        now = datetime.now(timezone.utc)

        if existing_actor is not None:
            # Update existing actor.
            existing_actor.confidence_score = confidence
            existing_actor.fingerprint = fingerprint
            existing_actor.label = label
            existing_actor.last_seen = now
            # Merge meta: preserve any existing keys.
            meta = existing_actor.meta or {}
            meta.update({
                "last_profiled": now.isoformat(),
                "campaign_ids": sorted(list({
                    r.campaign_id
                    for r in session.query(ActorCampaignModel)
                    .filter(ActorCampaignModel.actor_id == existing_actor.id)
                    .all()
                })),
            })
            existing_actor.meta = meta
            actors_updated += 1
            logger.debug(
                "Updated actor %s (%s) confidence=%.3f",
                existing_actor.id[:8], label, confidence,
            )
        else:
            # Create new actor linking both campaigns.
            actor_id = str(uuid.uuid4())
            actor = ActorModel(
                id=actor_id,
                label=label,
                fingerprint=fingerprint,
                confidence_score=confidence,
                first_seen=now,
                last_seen=now,
                meta={
                    "last_profiled": now.isoformat(),
                    "campaign_ids": [camp_a.id, camp_b.id],
                },
            )
            session.add(actor)
            session.flush()  # ensure actor.id is available

            # Create campaign links.
            session.add(ActorCampaignModel(
                actor_id=actor.id,
                campaign_id=camp_a.id,
            ))
            session.add(ActorCampaignModel(
                actor_id=actor.id,
                campaign_id=camp_b.id,
            ))
            actors_created += 1
            logger.info(
                "Created actor %s (%s) confidence=%.3f linking campaigns %s and %s",
                actor.id[:8], label, confidence, camp_a.id[:8], camp_b.id[:8],
            )

    session.flush()
    logger.info(
        "profile_actors complete: %d actors created, %d actors updated",
        actors_created, actors_updated,
    )
    return {"actors_created": actors_created, "actors_updated": actors_updated}


def get_actors(session) -> list[dict]:
    """List all actors with confidence and campaign count.

    Args:
        session: SQLAlchemy session.

    Returns:
        List of dicts, each with id, label, confidence_score, first_seen,
        last_seen, campaign_count.
    """
    from database import ActorCampaignModel, ActorModel  # type: ignore[import-untyped]

    actors = session.query(ActorModel).order_by(ActorModel.confidence_score.desc()).all()

    results = []
    for actor in actors:
        campaign_count = (
            session.query(ActorCampaignModel)
            .filter(ActorCampaignModel.actor_id == actor.id)
            .count()
        )
        results.append({
            "id": actor.id,
            "label": actor.label,
            "confidence_score": actor.confidence_score,
            "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
            "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
            "campaign_count": campaign_count,
        })

    logger.debug("get_actors: %d actors returned", len(results))
    return results


def get_actor_details(actor_id: str, session) -> dict:
    """Return full actor details including fingerprint breakdown and linked campaigns.

    Args:
        actor_id: UUID of the actor.
        session: SQLAlchemy session.

    Returns:
        Dict with actor info, fingerprint breakdown, linked campaigns, and
        confidence visualization data.  Returns empty dict if not found.
    """
    from database import (  # type: ignore[import-untyped]
        ActorCampaignModel,
        ActorModel,
        CampaignModel,
    )

    actor = session.query(ActorModel).get(actor_id)
    if actor is None:
        logger.warning("get_actor_details: actor %s not found", actor_id)
        return {}

    # Linked campaigns.
    campaign_links = (
        session.query(ActorCampaignModel)
        .filter(ActorCampaignModel.actor_id == actor_id)
        .all()
    )
    campaign_ids = [link.campaign_id for link in campaign_links]

    campaigns = []
    for cid in campaign_ids:
        camp = session.query(CampaignModel).get(cid)
        if camp is None:
            continue
        campaigns.append({
            "id": camp.id,
            "name": camp.name,
            "target_brand": camp.target_brand,
            "status": camp.status,
            "domain_count": camp.domain_count,
            "first_seen": camp.first_seen.isoformat() if camp.first_seen else None,
            "last_seen": camp.last_seen.isoformat() if camp.last_seen else None,
        })

    # Confidence visualization: break down the fingerprint signals.
    fingerprint = actor.fingerprint or {}
    shared_signals = fingerprint.get("shared_signals", {})
    confidence_vis = {
        "confidence_score": actor.confidence_score,
        "dimensions": {
            "shared_kit": {
                "value": shared_signals.get("shared_kit", 0.0),
                "weight": WEIGHT_SHARED_KIT,
                "contribution": round(
                    shared_signals.get("shared_kit", 0.0) * WEIGHT_SHARED_KIT, 4
                ),
            },
            "shared_infra": {
                "value": shared_signals.get("shared_infra", 0.0),
                "weight": WEIGHT_SHARED_INFRA,
                "contribution": round(
                    shared_signals.get("shared_infra", 0.0) * WEIGHT_SHARED_INFRA, 4
                ),
            },
            "shared_iocs": {
                "value": shared_signals.get("shared_iocs", 0.0),
                "weight": WEIGHT_SHARED_IOCS,
                "contribution": round(
                    shared_signals.get("shared_iocs", 0.0) * WEIGHT_SHARED_IOCS, 4
                ),
            },
            "temporal_overlap": {
                "value": shared_signals.get("temporal_overlap", 0.0),
                "weight": WEIGHT_TEMPORAL,
                "contribution": round(
                    shared_signals.get("temporal_overlap", 0.0) * WEIGHT_TEMPORAL, 4
                ),
            },
        },
        "label_threshold": (
            "LIKELY_SAME" if actor.confidence_score > LIKELY_SAME_THRESHOLD
            else "POSSIBLE"
        ),
    }

    return {
        "id": actor.id,
        "label": actor.label,
        "confidence_score": actor.confidence_score,
        "fingerprint": fingerprint,
        "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
        "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
        "meta": actor.meta or {},
        "campaigns": campaigns,
        "confidence_visualization": confidence_vis,
    }


def update_actor(actor_id: str, updates: dict, session) -> dict:
    """Update an actor's label and/or meta fields.

    Args:
        actor_id: UUID of the actor to update.
        updates: Dict with optional keys 'label' and/or 'meta'.
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Updated actor dict (same shape as get_actors item), or empty dict
        if the actor is not found.
    """
    from database import ActorModel  # type: ignore[import-untyped]

    actor = session.query(ActorModel).get(actor_id)
    if actor is None:
        logger.warning("update_actor: actor %s not found", actor_id)
        return {}

    if "label" in updates:
        actor.label = updates["label"]

    if "meta" in updates:
        # Merge meta rather than replacing entirely, so existing keys are
        # preserved unless explicitly overridden.
        existing_meta = actor.meta or {}
        existing_meta.update(updates["meta"])
        actor.meta = existing_meta

    actor.last_seen = datetime.now(timezone.utc)
    session.flush()

    logger.info("update_actor: actor %s updated", actor_id)
    return {
        "id": actor.id,
        "label": actor.label,
        "confidence_score": actor.confidence_score,
        "first_seen": actor.first_seen.isoformat() if actor.first_seen else None,
        "last_seen": actor.last_seen.isoformat() if actor.last_seen else None,
        "meta": actor.meta or {},
    }