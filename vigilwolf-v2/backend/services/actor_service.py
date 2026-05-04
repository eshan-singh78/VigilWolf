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
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Signal-dimension weights
# ---------------------------------------------------------------------------
WEIGHT_SHARED_KIT = 0.3
WEIGHT_SHARED_INFRA = 0.3
WEIGHT_SHARED_IOCS = 0.2
WEIGHT_TEMPORAL = 0.2

MAX_CAMPAIGNS_PER_PROFILE = 100
CAMPAIGN_WINDOW_DAYS = 30

# Confidence thresholds
CONFIDENCE_THRESHOLD = 0.6
LIKELY_SAME_THRESHOLD = 0.8
INFRA_CONFIDENCE_THRESHOLD = 0.7
MIN_INFRA_OVERLAP_COUNT = 3


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


def _build_fingerprint_fast(
    camp_a,
    camp_b,
    shared_kit: float,
    shared_infra: float,
    shared_iocs: float,
    temporal: float,
    infra_overlap_count: int,
    campaign_cluster_map: dict,
    cluster_type_map: dict,
    cluster_domain_map: dict,
    domain_registrar_map: dict,
    domain_asn_map: dict,
    domain_snapshot_map: dict,
    snapshot_ioc_map: dict,
    exfil_ioc_map: dict,
) -> dict:
    """Build the actor fingerprint JSON blob using pre-loaded data.

    Aggregates shared signals and derives preferred registrar, ASN, exfil
    channels, and target brands from the pre-loaded dictionaries, avoiding
    per-pair DB queries.
    """
    # F-2 fix: suppress infra signal in fingerprint when overlap count is too low
    effective_shared_infra = shared_infra if infra_overlap_count >= MIN_INFRA_OVERLAP_COUNT else 0.0
    fingerprint: dict = {
        "shared_signals": {
            "shared_kit": round(shared_kit, 4),
            "shared_infra": round(effective_shared_infra, 4),
            "shared_iocs": round(shared_iocs, 4),
            "temporal_overlap": round(temporal, 4),
        },
        "preferred_registrar": None,
        "preferred_asn": None,
        "exfil_channels": [],
        "target_brands": [],
    }

    # Collect all domain IDs across both campaigns' clusters.
    campaign_ids = [camp_a.id, camp_b.id]
    all_domain_ids: set[str] = set()
    for cid in campaign_ids:
        for cluster_id in campaign_cluster_map.get(cid, set()):
            all_domain_ids.update(cluster_domain_map.get(cluster_id, set()))

    # Preferred registrar and ASN from pre-loaded data.
    registrar_counts: dict[str, int] = {}
    asn_counts: dict[str, int] = {}
    for did in all_domain_ids:
        registrar = domain_registrar_map.get(did)
        if registrar:
            registrar_counts[registrar] = registrar_counts.get(registrar, 0) + 1
        asn = domain_asn_map.get(did)
        if asn:
            asn_counts[asn] = asn_counts.get(asn, 0) + 1

    if registrar_counts:
        fingerprint["preferred_registrar"] = max(
            registrar_counts, key=registrar_counts.get  # type: ignore[arg-type]
        )
    if asn_counts:
        fingerprint["preferred_asn"] = max(
            asn_counts, key=asn_counts.get  # type: ignore[arg-type]
        )

    # Exfil channels from pre-loaded data.
    exfil_values: set[str] = set()
    for did in all_domain_ids:
        for val in exfil_ioc_map.get(did, []):
            exfil_values.add(val)
    fingerprint["exfil_channels"] = sorted(exfil_values)[:20]

    # Target brands: combine from both campaigns.
    target_brands: set[str] = set()
    if camp_a.target_brand:
        target_brands.add(camp_a.target_brand)
    if camp_b.target_brand:
        target_brands.add(camp_b.target_brand)
    fingerprint["target_brands"] = sorted(target_brands)

    return fingerprint


# ---------------------------------------------------------------------------
# Union-find helpers for C-6 transitive closure
# ---------------------------------------------------------------------------


class _UnionFind:
    """Simple union-find (disjoint-set) with path compression and union by size."""

    def __init__(self):
        self._parent: dict[str, str] = {}
        self._size: dict[str, int] = {}

    def find(self, x: str) -> str:
        if x not in self._parent:
            self._parent[x] = x
            self._size[x] = 1
        if self._parent[x] != x:
            self._parent[x] = self.find(self._parent[x])  # path compression
        return self._parent[x]

    def union(self, x: str, y: str) -> None:
        rx, ry = self.find(x), self.find(y)
        if rx == ry:
            return
        # Union by size — attach smaller tree under larger.
        if self._size[rx] < self._size[ry]:
            rx, ry = ry, rx
        self._parent[ry] = rx
        self._size[rx] += self._size[ry]

    def components(self) -> dict[str, set[str]]:
        """Return {root: set(members)} for all connected components."""
        groups: dict[str, set[str]] = {}
        for node in self._parent:
            root = self.find(node)
            groups.setdefault(root, set()).add(node)
        return groups


def _merge_transitive_actors(session, actor_link_map: dict, all_actors: dict) -> None:
    """C-6: Merge actors that are transitively connected via shared campaigns.

    If actor X links campaigns A and B, and actor Y links campaigns B and C,
    then A-B-C are transitively connected and X/Y should be a single actor.
    Uses union-find on campaign IDs to find connected components, then merges
    all actors within each component into a single survivor (highest confidence).
    """
    from database import (  # type: ignore[import-untyped]
        ActorCampaignModel,
        ActorModel,
    )

    # 1. Build a graph of campaign connections via actors.
    #    For each actor, all campaigns it links form a clique.
    uf = _UnionFind()
    for _actor_id, camp_ids in actor_link_map.items():
        for i in range(len(camp_ids)):
            for j in range(i + 1, len(camp_ids)):
                uf.union(camp_ids[i], camp_ids[j])

    # 2. Group actors by the connected component of their campaigns.
    actor_by_component: dict[str, list[str]] = {}  # root campaign -> [actor_ids]
    for actor_id, camp_ids in actor_link_map.items():
        if not camp_ids:
            continue
        root = uf.find(camp_ids[0])
        actor_by_component.setdefault(root, []).append(actor_id)

    # 3. For each component with multiple actors, merge into a survivor.
    for root, actor_ids in actor_by_component.items():
        if len(actor_ids) < 2:
            continue

        # Pick survivor: highest confidence_score.
        candidates = [
            (aid, all_actors[aid].confidence_score)
            for aid in actor_ids
            if aid in all_actors
        ]
        if len(candidates) < 2:
            continue

        candidates.sort(key=lambda t: t[1], reverse=True)
        survivor_id = candidates[0][0]

        # Move all ActorCampaignModel links from non-survivors to survivor.
        for loser_id, _score in candidates[1:]:
            loser_links = (
                session.query(ActorCampaignModel)
                .filter(ActorCampaignModel.actor_id == loser_id)
                .all()
            )
            for link in loser_links:
                # Check if this campaign is already linked to the survivor.
                already_linked = (
                    session.query(ActorCampaignModel)
                    .filter(
                        ActorCampaignModel.actor_id == survivor_id,
                        ActorCampaignModel.campaign_id == link.campaign_id,
                    )
                    .first()
                )
                if already_linked is None:
                    session.add(ActorCampaignModel(
                        actor_id=survivor_id,
                        campaign_id=link.campaign_id,
                    ))
                session.delete(link)

            # Delete the loser actor.
            loser_actor = session.query(ActorModel).get(loser_id)
            if loser_actor is not None:
                logger.info(
                    "C-6: Merging actor %s (%s, conf=%.3f) into survivor %s (%s, conf=%.3f)",
                    loser_id[:8], loser_actor.label, loser_actor.confidence_score,
                    survivor_id[:8],
                    all_actors[survivor_id].label if survivor_id in all_actors else "?",
                    all_actors[survivor_id].confidence_score if survivor_id in all_actors else 0,
                )
                session.delete(loser_actor)

            # Update in-memory maps.
            if loser_id in all_actors:
                del all_actors[loser_id]
            if loser_id in actor_link_map:
                del actor_link_map[loser_id]

        # Update survivor's in-memory campaign list.
        survivor_links = (
            session.query(ActorCampaignModel)
            .filter(ActorCampaignModel.actor_id == survivor_id)
            .all()
        )
        survivor_camp_ids = [link.campaign_id for link in survivor_links]
        actor_link_map[survivor_id] = survivor_camp_ids
        if survivor_id in all_actors:
            survivor_actor = all_actors[survivor_id]
            survivor_actor.meta = {
                **(survivor_actor.meta or {}),
                "campaign_ids": sorted(survivor_camp_ids),
                "transitive_merge": True,
            }

    session.flush()


# ---------------------------------------------------------------------------
# Core service functions
# ---------------------------------------------------------------------------


def profile_actors(session) -> dict:
    """Profile threat actors by comparing every pair of campaigns.

    For each campaign pair, calculates a confidence score as a weighted sum
    of four signal dimensions:

        confidence = (shared_kit * 0.3) + (shared_infra * 0.3)
                   + (shared_iocs * 0.2) + (temporal_overlap * 0.2)

    If confidence > 0.6, an ActorModel is created (or updated) linking both
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

    campaign_cutoff = datetime.now(timezone.utc) - timedelta(days=CAMPAIGN_WINDOW_DAYS)
    campaigns = (
        session.query(CampaignModel)
        .filter(
            CampaignModel.status.in_(["active", "dormant"]),
            CampaignModel.last_seen >= campaign_cutoff,
        )
        .order_by(CampaignModel.last_seen.desc())
        .all()
    )
    if len(campaigns) < 2:
        logger.info("profile_actors: fewer than 2 campaigns, nothing to profile.")
        return {"actors_created": 0, "actors_updated": 0}

    if len(campaigns) > MAX_CAMPAIGNS_PER_PROFILE:
        logger.warning(
            "profile_actors: %d campaigns exceeds MAX_CAMPAIGNS_PER_PROFILE (%d); "
            "using first %d campaigns only.",
            len(campaigns), MAX_CAMPAIGNS_PER_PROFILE, MAX_CAMPAIGNS_PER_PROFILE,
        )
        campaigns = campaigns[:MAX_CAMPAIGNS_PER_PROFILE]

    # Pre-load all data needed for pairwise comparison
    from database import (  # type: ignore[import-untyped]
        CampaignClusterModel,
        ClusterMemberModel,
        ClusterModel,
        DomainIpModel,
        DomainModel,
        IocModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    # Pre-load campaign -> cluster IDs (filtered to our campaigns only)
    campaign_cluster_map: dict[str, set[str]] = {}
    campaign_ids = {c.id for c in campaigns}
    if campaign_ids:
        all_cluster_links = session.query(CampaignClusterModel).filter(
            CampaignClusterModel.campaign_id.in_(campaign_ids)
        ).all()
        for link in all_cluster_links:
            campaign_cluster_map.setdefault(link.campaign_id, set()).add(link.cluster_id)

    # Collect all cluster IDs referenced by our campaigns
    relevant_cluster_ids: set[str] = set()
    for cluster_ids in campaign_cluster_map.values():
        relevant_cluster_ids.update(cluster_ids)

    # Pre-load cluster types for relevant clusters only
    cluster_type_map: dict[str, str] = {}
    if relevant_cluster_ids:
        clusters = session.query(ClusterModel).filter(
            ClusterModel.id.in_(relevant_cluster_ids)
        ).all()
        for c in clusters:
            cluster_type_map[c.id] = c.cluster_type

    # Pre-load cluster -> domain mappings for relevant clusters only
    cluster_domain_map: dict[str, set[str]] = {}
    if relevant_cluster_ids:
        members = session.query(ClusterMemberModel).filter(
            ClusterMemberModel.cluster_id.in_(relevant_cluster_ids)
        ).all()
        for m in members:
            cluster_domain_map.setdefault(m.cluster_id, set()).add(m.domain_id)

    # C-2 fix: Collect relevant domain IDs from clusters linked to active campaigns
    relevant_domain_ids: set[str] = set()
    for cluster_ids in campaign_cluster_map.values():
        for cluster_id in cluster_ids:
            relevant_domain_ids.update(cluster_domain_map.get(cluster_id, set()))

    # Pre-load domain -> snapshot mappings (filtered to relevant domains only)
    domain_snapshot_map: dict[str, set[str]] = {}
    if relevant_domain_ids:
        filtered_snapshots = session.query(SnapshotModel).filter(
            SnapshotModel.domain_id.in_(relevant_domain_ids)
        ).all()
        for s in filtered_snapshots:
            domain_snapshot_map.setdefault(s.domain_id, set()).add(s.id)

    # C-2 fix: Collect relevant snapshot IDs from filtered domain_snapshot_map
    relevant_snapshot_ids: set[str] = set()
    for sids in domain_snapshot_map.values():
        relevant_snapshot_ids.update(sids)

    # H-7 fix: Pre-load snapshot -> IOC (type, value) mappings using value-based
    # keys instead of database IDs, so Jaccard similarity compares IOC content
    # rather than relying on fragile row identity.
    snapshot_ioc_map: dict[str, set[tuple[str, str]]] = {}
    if relevant_snapshot_ids:
        filtered_ioc_rows = (
            session.query(IocOccurrenceModel.snapshot_id, IocModel.type, IocModel.value)
            .join(IocModel, IocOccurrenceModel.ioc_id == IocModel.id)
            .filter(IocOccurrenceModel.snapshot_id.in_(relevant_snapshot_ids))
            .all()
        )
        for row in filtered_ioc_rows:
            snapshot_ioc_map.setdefault(row.snapshot_id, set()).add((row.type, row.value))

    # Pre-compute campaign -> IOC (type, value) mapping
    campaign_ioc_map: dict[str, set[tuple[str, str]]] = {}
    for camp in campaigns:
        camp_clusters = campaign_cluster_map.get(camp.id, set())
        domain_ids: set[str] = set()
        for cid in camp_clusters:
            domain_ids.update(cluster_domain_map.get(cid, set()))

        ioc_tuples: set[tuple[str, str]] = set()
        for did in domain_ids:
            for sid in domain_snapshot_map.get(did, set()):
                ioc_tuples.update(snapshot_ioc_map.get(sid, set()))
        campaign_ioc_map[camp.id] = ioc_tuples

    # Pre-load domain attributes for fingerprint building
    domain_registrar_map: dict[str, str | None] = {}
    domain_asn_map: dict[str, str | None] = {}
    all_domain_ids_in_clusters = set()
    for dids in cluster_domain_map.values():
        all_domain_ids_in_clusters.update(dids)

    all_domains = session.query(DomainModel).filter(
        DomainModel.id.in_(all_domain_ids_in_clusters)
    ).all() if all_domain_ids_in_clusters else []
    for d in all_domains:
        domain_registrar_map[d.id] = getattr(d, "registrar", None)

    all_ips = (
        session.query(DomainIpModel)
        .filter(DomainIpModel.domain_id.in_(all_domain_ids_in_clusters))
        .all()
    )
    for ip_row in all_ips:
        if hasattr(ip_row, "asn") and ip_row.asn:
            domain_asn_map.setdefault(ip_row.domain_id, str(ip_row.asn))

    # Pre-load exfil IOCs for fingerprint building (single filtered query)
    exfil_ioc_map: dict[str, list[str]] = {}  # domain_id -> [ioc_value, ...]
    if relevant_domain_ids:
        exfil_rows = (
            session.query(SnapshotModel.domain_id, IocModel.value)
            .join(IocOccurrenceModel, IocOccurrenceModel.snapshot_id == SnapshotModel.id)
            .join(IocModel, IocOccurrenceModel.ioc_id == IocModel.id)
            .filter(
                IocOccurrenceModel.role == "exfil_endpoint",
                IocModel.type == "url",
                SnapshotModel.domain_id.in_(relevant_domain_ids),
            )
            .distinct()
            .all()
        )
        for row in exfil_rows:
            exfil_ioc_map.setdefault(row.domain_id, []).append(row.value)

    # Pre-load actor-campaign mappings scoped to active campaigns only
    actor_campaign_pairs: dict[frozenset[str], str] = {}  # {camp_id_a, camp_id_b} -> actor_id
    all_actor_links = session.query(ActorCampaignModel).filter(
        ActorCampaignModel.campaign_id.in_(campaign_ids)
    ).all()
    actor_ids = {link.actor_id for link in all_actor_links}
    actor_link_map: dict[str, list[str]] = {}  # actor_id -> [campaign_ids]
    for link in all_actor_links:
        actor_link_map.setdefault(link.actor_id, []).append(link.campaign_id)

    for actor_id, camp_ids in actor_link_map.items():
        for i in range(len(camp_ids)):
            for j in range(i + 1, len(camp_ids)):
                pair_key = frozenset([camp_ids[i], camp_ids[j]])
                actor_campaign_pairs[pair_key] = actor_id

    # Pre-load only actors linked to active campaigns
    all_actors = {a.id: a for a in session.query(ActorModel).filter(
        ActorModel.id.in_(actor_ids)
    ).all()} if actor_ids else {}

    actors_created = 0
    actors_updated = 0

    # Compare every unique pair of campaigns.
    for camp_a, camp_b in itertools.combinations(campaigns, 2):
        sig_a = camp_a.kit_signature
        sig_b = camp_b.kit_signature
        shared_kit = 1.0 if (sig_a and sig_b and sig_a == sig_b) else 0.0

        # Use pre-loaded cluster data
        clusters_a = campaign_cluster_map.get(camp_a.id, set())
        clusters_b = campaign_cluster_map.get(camp_b.id, set())
        infra_a = {cid for cid in clusters_a if cluster_type_map.get(cid) == "infra"}
        infra_b = {cid for cid in clusters_b if cluster_type_map.get(cid) == "infra"}
        infra_overlap_count = len(infra_a & infra_b)
        shared_infra = _jaccard(infra_a, infra_b)
        # F-2 fix: suppress infra signal when overlap is too sparse or confidence too low
        if shared_infra < INFRA_CONFIDENCE_THRESHOLD or infra_overlap_count < MIN_INFRA_OVERLAP_COUNT:
            shared_infra = 0.0

        iocs_a = campaign_ioc_map.get(camp_a.id, set())
        iocs_b = campaign_ioc_map.get(camp_b.id, set())
        shared_iocs = _jaccard(iocs_a, iocs_b)
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

        # Build fingerprint using pre-loaded data (no DB queries)
        fingerprint = _build_fingerprint_fast(
            camp_a, camp_b, shared_kit, shared_infra, shared_iocs, temporal,
            infra_overlap_count,
            campaign_cluster_map, cluster_type_map, cluster_domain_map,
            domain_registrar_map, domain_asn_map, domain_snapshot_map,
            snapshot_ioc_map, exfil_ioc_map,
        )
        label = _generate_label(confidence, fingerprint)

        now = datetime.now(timezone.utc)

        # Check if an actor already links these two campaigns using pre-loaded data
        pair_key = frozenset([camp_a.id, camp_b.id])
        existing_actor_id = actor_campaign_pairs.get(pair_key)

        if existing_actor_id is not None and existing_actor_id in all_actors:
            # Update existing actor.
            existing_actor = all_actors[existing_actor_id]
            existing_actor.confidence_score = confidence
            existing_actor.fingerprint = fingerprint
            existing_actor.label = label
            existing_actor.last_seen = now
            existing_actor.meta = {
                **(existing_actor.meta or {}),
                "last_profiled": now.isoformat(),
                "campaign_ids": sorted(actor_link_map.get(existing_actor_id, [])),
            }
            # F-5: Log degradation warning when confidence drops below threshold.
            if existing_actor.confidence_score < CONFIDENCE_THRESHOLD:
                logger.warning(
                    "Actor %s (%s) confidence %.3f dropped below threshold %.1f — low-confidence degradation",
                    existing_actor.id[:8], existing_actor.label,
                    existing_actor.confidence_score, CONFIDENCE_THRESHOLD,
                )
                existing_actor.meta = {
                    **(existing_actor.meta or {}),
                    "degraded": True,
                    "degraded_at": now.isoformat(),
                }
            actors_updated += 1
            logger.debug(
                "Updated actor %s (%s) confidence=%.3f",
                existing_actor.id[:8], label, confidence,
            )
        else:
            # Create new actor linking both campaigns.
            actor_id = str(uuid.uuid4())
            try:
                with session.begin_nested():
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
                # Update pre-loaded data for subsequent pairs
                all_actors[actor.id] = actor
                actor_link_map[actor.id] = [camp_a.id, camp_b.id]
                actor_campaign_pairs[frozenset([camp_a.id, camp_b.id])] = actor.id

                logger.info(
                    "Created actor %s (%s) confidence=%.3f linking campaigns %s and %s",
                    actor.id[:8], label, confidence, camp_a.id[:8], camp_b.id[:8],
                )
            except IntegrityError:
                # C-5 fix: Use composite campaign-ID dedup instead of label-based.
                # Check if an ActorCampaignModel already links both campaigns.
                session.rollback()
                existing_link = (
                    session.query(ActorCampaignModel)
                    .filter(ActorCampaignModel.campaign_id == camp_a.id)
                    .first()
                )
                # Find an actor that links both campaign IDs.
                linked_actor_id = None
                if existing_link is not None:
                    # Check all actors linked to camp_a to see if any also link camp_b.
                    a_links = session.query(ActorCampaignModel).filter(
                        ActorCampaignModel.campaign_id == camp_a.id,
                    ).all()
                    for al in a_links:
                        b_link = session.query(ActorCampaignModel).filter(
                            ActorCampaignModel.actor_id == al.actor_id,
                            ActorCampaignModel.campaign_id == camp_b.id,
                        ).first()
                        if b_link is not None:
                            linked_actor_id = al.actor_id
                            break

                if linked_actor_id is not None:
                    # Pair already linked — just update confidence.
                    logger.debug(
                        "Campaign pair %s/%s already linked by actor %s — updating",
                        camp_a.id[:8], camp_b.id[:8], linked_actor_id[:8],
                    )
                    if linked_actor_id in all_actors:
                        existing_actor = all_actors[linked_actor_id]
                        existing_actor.confidence_score = confidence
                        existing_actor.fingerprint = fingerprint
                        existing_actor.label = label
                        existing_actor.last_seen = now
                        existing_actor.meta = {
                            **(existing_actor.meta or {}),
                            "last_profiled": now.isoformat(),
                        }
                        actors_updated += 1
                else:
                    # No existing link — create a new actor with a unique label.
                    unique_label = f"{label}_{uuid.uuid4().hex[:6]}"
                    logger.info(
                        "Label conflict for campaign pair %s/%s — creating actor with unique label %s",
                        camp_a.id[:8], camp_b.id[:8], unique_label,
                    )
                    actor_id = str(uuid.uuid4())
                    try:
                        with session.begin_nested():
                            actor = ActorModel(
                                id=actor_id,
                                label=unique_label,
                                fingerprint=fingerprint,
                                confidence_score=confidence,
                                first_seen=now,
                                last_seen=now,
                                meta={
                                    "last_profiled": now.isoformat(),
                                    "campaign_ids": [camp_a.id, camp_b.id],
                                    "label_conflict_resolution": True,
                                },
                            )
                            session.add(actor)
                            session.flush()

                            session.add(ActorCampaignModel(
                                actor_id=actor.id,
                                campaign_id=camp_a.id,
                            ))
                            session.add(ActorCampaignModel(
                                actor_id=actor.id,
                                campaign_id=camp_b.id,
                            ))
                        actors_created += 1
                        all_actors[actor.id] = actor
                        actor_link_map[actor.id] = [camp_a.id, camp_b.id]
                        actor_campaign_pairs[frozenset([camp_a.id, camp_b.id])] = actor.id
                    except Exception:
                        logger.debug(
                            "Failed to create actor for campaign pair %s/%s after label conflict",
                            camp_a.id[:8], camp_b.id[:8],
                        )

    session.flush()

    # C-6: Union-find transitive closure — merge actors that are linked to
    # campaigns in the same connected component.  If campaigns A-B share an
    # actor and B-C share another actor, all three campaigns should belong to
    # one actor (the survivor).
    _merge_transitive_actors(session, actor_link_map, all_actors)

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