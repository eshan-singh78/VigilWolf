"""Campaign service for VigilWolf v2.

Auto-detects phishing campaigns from clusters and time windows.  Consumes
ClusterModel / ClusterMemberModel rows produced by the clustering service,
identifies coordinated activity targeting specific brands, and manages
CampaignModel / CampaignClusterModel rows for downstream consumption by the
alert and actor-profiling services.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import urlparse

from sqlalchemy import func, or_

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Recheck interval
# ---------------------------------------------------------------------------

CAMPAIGN_RECHECK_INTERVAL_HOURS = 24

# ---------------------------------------------------------------------------
# Brand detection
# ---------------------------------------------------------------------------

# Keywords that are too generic or represent infrastructure, not phishing targets.
_BRAND_DENYLIST = {
    "google", "cloudflare", "akamai", "amazon", "aws", "azure",
    "microsoft", "apple", "github", "gitlab", "docker",
    "icloud",
    "npm", "jsdelivr", "unpkg", "cdnjs",
    "go", "me", "it", "be", "at", "us", "uk", "de", "fr",
    "my", "tv", "io", "ai", "co",
}

# Minimum keyword length — keywords shorter than 4 chars match too broadly.
_BRAND_MIN_LENGTH = 4

# Known legitimate infrastructure domains that must never be used for brand
# detection.  These are real domains owned by the brands they reference, so
# matching them would produce false campaigns.
_LEGITIMATE_DOMAIN_DENYLIST = {
    "apple.com", "icloud.com", "usps.com", "dhl.com", "fedex.com",
    "ups.com", "google.com", "microsoft.com", "amazon.com",
    "netflix.com", "linkedin.com", "facebook.com", "twitter.com",
    "x.com", "stripe.com", "shopify.com", "citibank.com",
}


def _is_denied_domain(hostname: str) -> bool:
    """Check if a hostname matches the legitimate domain denylist.

    Supports exact match and subdomain suffix match.
    E.g., login.apple.com matches apple.com, accounts.google.com matches google.com.
    """
    if not hostname:
        return False
    hostname_lower = hostname.lower()
    for denied in _LEGITIMATE_DOMAIN_DENYLIST:
        # Exact match
        if hostname_lower == denied:
            return True
        # Subdomain match: hostname ends with .denied
        if hostname_lower.endswith(f".{denied}"):
            return True
    return False

# Ordered by specificity — longer keywords first to avoid partial matches.
BRAND_KEYWORDS: list[tuple[str, str]] = [
    ("paypal", "PAYPAL"),
    ("wellsfargo", "WELLSFARGO"),
    ("chase", "CHASE"),
    ("bankofamerica", "BANKOFAMERICA"),
    ("bofa", "BANKOFAMERICA"),
    ("citibank", "CITIBANK"),
    ("citi", "CITIBANK"),
    ("usbank", "USBANK"),
    ("pncbank", "PNC"),
    ("pnc", "PNC"),
    ("tdbank", "TD"),
    ("schwab", "SCHWAB"),
    ("amex", "AMEX"),
    ("americanexpress", "AMEX"),
    ("apple", "APPLE"),
    ("icloud", "APPLE"),
    ("microsoft", "MICROSOFT"),
    ("office365", "MICROSOFT"),
    ("outlook", "MICROSOFT"),
    ("amazon", "AMAZON"),
    ("netflix", "NETFLIX"),
    ("google", "GOOGLE"),
    ("gmail", "GOOGLE"),
    ("facebook", "META"),
    ("meta", "META"),
    ("instagram", "META"),
    ("whatsapp", "META"),
    ("twitter", "X"),
    ("x.com", "X"),
    ("linkedin", "LINKEDIN"),
    ("dhl", "DHL"),
    ("fedex", "FEDEX"),
    ("ups", "UPS"),
    ("usps", "USPS"),
    ("royalmail", "ROYALMAIL"),
    ("santander", "SANTANDER"),
    ("barclays", "BARCLAYS"),
    ("hsbc", "HSBC"),
    ("lloyds", "LLOYDS"),
    ("natwest", "NATWEST"),
    ("revolut", "REVOLUT"),
    ("chime", "CHIME"),
    ("venmo", "VENMO"),
    ("cashapp", "CASHAPP"),
    ("zelle", "ZELLE"),
    ("coinbase", "COINBASE"),
    ("binance", "BINANCE"),
    ("kraken", "KRAKEN"),
    ("stripe", "STRIPE"),
    ("shopify", "SHOPIFY"),
]

# How recent a cluster must be to qualify for campaign detection.
DETECTION_WINDOW_DAYS = 30

# If no new domains appear in this window, the campaign goes dormant.
DORMANT_THRESHOLD_DAYS = 14


def _detect_brand(domain_urls: list[str]) -> Optional[str]:
    """Attempt to identify the targeted brand from domain hostnames.

    Extracts the hostname from each URL and checks for brand keyword
    matches against the hostname only (not the path/query), reducing
    false positives from URL paths like /uploads/ or /verify/.

    Uses a scoring heuristic to pick the best match when multiple brands
    are detected: exact SLD match = 3 points, subdomain match = 1 point,
    longer keyword = +1 point.  Returns the highest-scoring brand.

    Short keywords (< 4 chars) and denylisted infrastructure/generic
    terms are skipped to prevent false positives.
    """
    hostnames: list[str] = []
    for url in domain_urls:
        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            if hostname:
                # Strip www. prefix for matching
                if hostname.startswith("www."):
                    hostname = hostname[4:]
                hostnames.append(hostname)
        except Exception:
            continue

    if not hostnames:
        return None

    # Exclude known legitimate infrastructure domains before brand matching.
    hostnames = [h for h in hostnames if not _is_denied_domain(h)]
    if not hostnames:
        return None

    combined = " ".join(hostnames)

    # Collect ALL matching brands with scores using label-level matching.
    # Label-level matching prevents false positives like "subchase.example.com"
    # matching CHASE — only exact label or hyphen-delimited part matches count.
    brand_scores: dict[str, int] = {}
    for keyword, brand in BRAND_KEYWORDS:
        # Skip short keywords and denylisted terms to reduce false positives.
        if len(keyword) < _BRAND_MIN_LENGTH or keyword.lower() in _BRAND_DENYLIST:
            continue
        # Match keyword against individual labels (dot-separated parts)
        # of each hostname, and also hyphen-delimited parts within labels.
        matched = False
        for h in hostnames:
            labels = h.split(".")
            sld = labels[-2] if len(labels) >= 2 else h
            for label in labels:
                is_sld = (label == sld)
                if keyword == label:
                    # Exact full-label match — strongest signal
                    matched = True
                    if is_sld:
                        brand_scores[brand] = max(brand_scores.get(brand, 0), 3)
                    else:
                        brand_scores[brand] = max(brand_scores.get(brand, 0), 1)
                else:
                    # Check hyphen-delimited parts within this label.
                    # "chase-login" splits to ["chase", "login"] — "chase" matches.
                    # "subchase" splits to ["subchase"] — "chase" does NOT match.
                    parts = label.split("-")
                    if keyword in parts:
                        matched = True
                        brand_scores[brand] = max(brand_scores.get(brand, 0), 1)
        if matched and len(keyword) >= 6:
            # Longer keywords are more specific and deserve a bonus
            brand_scores[brand] = brand_scores.get(brand, 0) + 1

    if not brand_scores:
        return None

    # Return the brand with the highest score.
    return max(brand_scores, key=brand_scores.get)


def _generate_campaign_name(brand: str) -> str:
    """Auto-generate a campaign name in the format BRAND_PHISH_YYYYWNN.

    Uses the ISO week number for the date suffix, so campaigns targeting the
    same brand within the same week share a name base (the uniqueness loop
    appends _1, _2 etc. if needed).

    Args:
        brand: Uppercased brand label.

    Returns:
        Campaign name string, e.g. "PAYPAL_PHISH_2026W18".
    """
    now = datetime.now(timezone.utc)
    iso_year, iso_week, _ = now.isocalendar()
    return f"{brand}_PHISH_{iso_year}W{iso_week:02d}"


# ---------------------------------------------------------------------------
# Campaign detection
# ---------------------------------------------------------------------------


def _count_shared_iocs(campaign, cluster, session, campaign_ioc_sets: dict | None = None) -> int:
    """Count IOCs shared between a campaign and a cluster using value-based comparison.

    Uses pre-loaded campaign IOC sets when available to avoid per-pair DB queries.

    Args:
        campaign: CampaignModel instance.
        cluster: ClusterModel instance.
        session: SQLAlchemy session.
        campaign_ioc_sets: Optional pre-loaded dict of campaign_id -> IOC set.

    Returns:
        Number of shared (type, value) IOC pairs.
    """
    from database import (  # type: ignore[import-untyped]
        ClusterMemberModel,
        IocModel,
        IocOccurrenceModel,
        SnapshotModel,
    )

    # Use pre-loaded campaign IOC set if available
    if campaign_ioc_sets is not None and campaign.id in campaign_ioc_sets:
        campaign_iocs = campaign_ioc_sets[campaign.id]
    else:
        # Fallback: load from DB (backward compatibility)
        from database import CampaignClusterModel, ClusterModel  # type: ignore[import-untyped]
        domain_ids_q = (
            session.query(ClusterMemberModel.domain_id)
            .join(ClusterModel, ClusterMemberModel.cluster_id == ClusterModel.id)
            .join(CampaignClusterModel, CampaignClusterModel.cluster_id == ClusterModel.id)
            .filter(CampaignClusterModel.campaign_id == campaign.id)
        ).all()
        domain_ids = {row[0] for row in domain_ids_q}

        if not domain_ids:
            return 0
        snapshot_ids_q = (
            session.query(SnapshotModel.id)
            .filter(SnapshotModel.domain_id.in_(domain_ids))
        ).all()
        snapshot_ids = {row[0] for row in snapshot_ids_q}
        if not snapshot_ids:
            return 0
        rows = (
            session.query(IocModel.type, IocModel.value)
            .join(IocOccurrenceModel, IocOccurrenceModel.ioc_id == IocModel.id)
            .filter(IocOccurrenceModel.snapshot_id.in_(snapshot_ids))
        ).all()
        campaign_iocs = {(row[0], row[1]) for row in rows}

    # Always load cluster IOCs from DB (they're the new cluster being evaluated)
    cluster_domain_ids_q = (
        session.query(ClusterMemberModel.domain_id)
        .filter(ClusterMemberModel.cluster_id == cluster.id)
    ).all()
    cluster_domain_ids = {row[0] for row in cluster_domain_ids_q}
    if not cluster_domain_ids:
        return 0
    cluster_snapshot_ids_q = (
        session.query(SnapshotModel.id)
        .filter(SnapshotModel.domain_id.in_(cluster_domain_ids))
    ).all()
    cluster_snapshot_ids = {row[0] for row in cluster_snapshot_ids_q}
    if not cluster_snapshot_ids:
        return 0
    cluster_rows = (
        session.query(IocModel.type, IocModel.value)
        .join(IocOccurrenceModel, IocOccurrenceModel.ioc_id == IocModel.id)
        .filter(IocOccurrenceModel.snapshot_id.in_(cluster_snapshot_ids))
    ).all()
    cluster_iocs = {(row[0], row[1]) for row in cluster_rows}

    return len(campaign_iocs & cluster_iocs)


def _recompute_domain_count(campaign, session) -> int:
    """Recompute and persist the domain_count from all linked clusters.

    Counts distinct domain IDs across every cluster linked to the campaign,
    then writes the result back to ``campaign.domain_count`` and returns it.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignClusterModel,
        ClusterMemberModel,
        ClusterModel,
    )

    domain_count_result = (
        session.query(func.count(func.distinct(ClusterMemberModel.domain_id)))
        .join(ClusterModel, ClusterMemberModel.cluster_id == ClusterModel.id)
        .join(CampaignClusterModel, CampaignClusterModel.cluster_id == ClusterModel.id)
        .filter(CampaignClusterModel.campaign_id == campaign.id)
        .scalar()
    )
    campaign.domain_count = domain_count_result or 0
    return campaign.domain_count


def detect_campaigns(session) -> dict:
    """Detect phishing campaigns from html_similarity clusters.

    Finds html_similarity clusters with 3+ domains that appeared within the
    last 30 days.  For each qualifying cluster, either creates a new campaign
    or updates the existing linked campaign.

    New campaigns:
      - Target brand is inferred from cluster domain names.
      - Name is auto-generated as ``{BRAND}_PHISH_{MMDD}``.
      - If no brand is detected, the brand defaults to "UNKNOWN" and the
        campaign name uses "UNKNOWN" as the prefix.
      - The cluster is linked via CampaignClusterModel.

    Existing campaigns:
      - domain_count and last_seen are refreshed.
      - Status is set to "dormant" if no new domains have appeared in 14 days.

    Args:
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Dict with ``campaigns_created`` and ``campaigns_updated`` counts.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignClusterModel,
        CampaignModel,
        ClusterMemberModel,
        ClusterModel,
        DomainModel,
    )

    cutoff = datetime.now(timezone.utc) - timedelta(days=DETECTION_WINDOW_DAYS)
    recheck_cutoff = datetime.now(timezone.utc) - timedelta(hours=CAMPAIGN_RECHECK_INTERVAL_HOURS)

    # Find qualifying clusters: html_similarity and phishkit, 3+ domains,
    # within window, and not already checked within the recheck interval.
    # Phishkit clusters indicate known phishing kit reuse — strong campaign signal.
    clusters = (
        session.query(ClusterModel)
        .filter(
            ClusterModel.cluster_type.in_(["html_similarity", "phishkit"]),
            ClusterModel.domain_count >= 3,
            ClusterModel.last_seen >= cutoff,
            or_(
                ClusterModel.last_campaign_check.is_(None),
                ClusterModel.last_campaign_check < recheck_cutoff,
            ),
        )
        .all()
    )

    campaigns_created = 0
    campaigns_updated = 0

    # Pre-load IOC sets for all active campaigns to avoid per-pair DB queries (S-7).
    active_campaign_ids = {c.id for c in session.query(CampaignModel).filter(
        CampaignModel.status.in_(["active", "dormant"]),
    ).all()} if clusters else set()

    campaign_ioc_sets: dict[str, set[tuple[str, str]]] = {}
    if active_campaign_ids:
        # Bulk load all campaign -> cluster links
        all_cc_links = session.query(CampaignClusterModel).filter(
            CampaignClusterModel.campaign_id.in_(active_campaign_ids)
        ).all()
        campaign_cluster_ids_map: dict[str, set[str]] = {}
        relevant_cluster_ids_for_ioc: set[str] = set()
        for link in all_cc_links:
            campaign_cluster_ids_map.setdefault(link.campaign_id, set()).add(link.cluster_id)
            relevant_cluster_ids_for_ioc.add(link.cluster_id)

        # Bulk load cluster -> domain mappings
        cluster_domain_map_camp: dict[str, set[str]] = {}
        if relevant_cluster_ids_for_ioc:
            members = session.query(ClusterMemberModel).filter(
                ClusterMemberModel.cluster_id.in_(relevant_cluster_ids_for_ioc)
            ).all()
            for m in members:
                cluster_domain_map_camp.setdefault(m.cluster_id, set()).add(m.domain_id)

        # Collect all relevant domain IDs
        all_domain_ids_camp: set[str] = set()
        for domain_ids in cluster_domain_map_camp.values():
            all_domain_ids_camp.update(domain_ids)

        # Bulk load domain -> snapshot mappings
        domain_snapshot_map_camp: dict[str, set[str]] = {}
        if all_domain_ids_camp:
            snaps = session.query(SnapshotModel).filter(
                SnapshotModel.domain_id.in_(all_domain_ids_camp)
            ).all()
            for s in snaps:
                domain_snapshot_map_camp.setdefault(s.domain_id, set()).add(s.id)

        # Collect all snapshot IDs
        all_snapshot_ids_camp: set[str] = set()
        for sids in domain_snapshot_map_camp.values():
            all_snapshot_ids_camp.update(sids)

        # Bulk load snapshot -> IOC (type, value) tuples using a subquery
        # join instead of .in_() with a potentially huge ID set (P1-7).
        if all_snapshot_ids_camp:
            # Use a subquery on snapshot_id to avoid oversized IN clauses
            snapshot_subq = (
                session.query(SnapshotModel.id)
                .filter(SnapshotModel.id.in_(all_snapshot_ids_camp))
                .subquery()
            )
            ioc_rows = (
                session.query(IocModel.type, IocModel.value, IocOccurrenceModel.snapshot_id)
                .join(IocOccurrenceModel, IocOccurrenceModel.ioc_id == IocModel.id)
                .join(snapshot_subq, snapshot_subq.c.id == IocOccurrenceModel.snapshot_id)
                .all()
            )
            snapshot_ioc_map_camp: dict[str, set[tuple[str, str]]] = {}
            for row in ioc_rows:
                snapshot_ioc_map_camp.setdefault(row.snapshot_id, set()).add((row.type, row.value))

            # Build campaign -> IOC set mapping
            for camp_id, c_ids in campaign_cluster_ids_map.items():
                ioc_set: set[tuple[str, str]] = set()
                domain_ids_for_camp: set[str] = set()
                for cid in c_ids:
                    domain_ids_for_camp.update(cluster_domain_map_camp.get(cid, set()))
                for did in domain_ids_for_camp:
                    for sid in domain_snapshot_map_camp.get(did, set()):
                        ioc_set.update(snapshot_ioc_map_camp.get(sid, set()))
                campaign_ioc_sets[camp_id] = ioc_set

    for cluster in clusters:
        # Track whether this cluster was actually processed
        cluster_processed = False

        # Check if this cluster is already linked to a campaign.
        existing_link = (
            session.query(CampaignClusterModel)
            .filter(CampaignClusterModel.cluster_id == cluster.id)
            .first()
        )

        if existing_link is not None:
            # Update the linked campaign.
            campaign = (
                session.query(CampaignModel)
                .filter(CampaignModel.id == existing_link.campaign_id)
                .first()
            )
            if campaign is None:
                logger.warning(
                    "CampaignClusterModel points to missing campaign %s; skipping.",
                    existing_link.campaign_id,
                )
                continue

            _recompute_domain_count(campaign, session)
            campaign.last_seen = max(campaign.last_seen or cluster.last_seen, cluster.last_seen)

            # Determine dormancy or re-activation (C-4: campaign-wide check).
            dormant_cutoff = datetime.now(timezone.utc) - timedelta(days=DORMANT_THRESHOLD_DAYS)
            max_last_seen = (
                session.query(func.max(ClusterModel.last_seen))
                .join(CampaignClusterModel, CampaignClusterModel.cluster_id == ClusterModel.id)
                .filter(CampaignClusterModel.campaign_id == campaign.id)
                .scalar()
            )
            if max_last_seen and max_last_seen < dormant_cutoff and campaign.status == "active":
                campaign.status = "dormant"
                logger.info(
                    "Campaign %s (%s) marked dormant — no new domains since %s",
                    campaign.id, campaign.name, cluster.last_seen.isoformat(),
                )
            elif cluster.last_seen >= dormant_cutoff and campaign.status == "dormant":
                campaign.status = "active"
                _recompute_domain_count(campaign, session)
                logger.info(
                    "Campaign %s (%s) re-activated — new domains detected",
                    campaign.id, campaign.name,
                )

            campaigns_updated += 1
            cluster_processed = True
            logger.debug(
                "Updated campaign %s: domain_count=%d, last_seen=%s, status=%s",
                campaign.id, campaign.domain_count,
                campaign.last_seen.isoformat() if campaign.last_seen else None,
                campaign.status,
            )
        else:
            # New campaign needed — resolve brand from member domains.
            member_rows = (
                session.query(DomainModel)
                .join(
                    ClusterMemberModel,
                    DomainModel.id == ClusterMemberModel.domain_id,
                )
                .filter(ClusterMemberModel.cluster_id == cluster.id)
                .all()
            )
            domain_urls = [d.url for d in member_rows]
            brand = _detect_brand(domain_urls) or "UNKNOWN"

            # Check for an existing active campaign targeting the same brand.
            existing_brand_campaign = (
                session.query(CampaignModel)
                .filter(
                    CampaignModel.target_brand == brand,
                    CampaignModel.status.in_(["active", "dormant"]),
                )
                .order_by(CampaignModel.last_seen.desc())
                .first()
            )

            if existing_brand_campaign is not None:
                # C-2: Require similarity signal beyond brand match before merging.
                cluster_sig = cluster.signature_hash
                campaign_sig = existing_brand_campaign.kit_signature
                should_merge = False

                if cluster_sig and campaign_sig:
                    if cluster_sig == campaign_sig:
                        # Both have signatures and they match — merge.
                        should_merge = True
                    else:
                        # Signatures explicitly mismatch — separate campaigns.
                        logger.info(
                            "Kit signature mismatch for cluster %s vs campaign %s (brand=%s) — creating separate campaign",
                            cluster.id[:8], existing_brand_campaign.id[:8], brand,
                        )
                else:
                    # At least one side lacks a signature — require IOC overlap.
                    shared_count = _count_shared_iocs(existing_brand_campaign, cluster, session, campaign_ioc_sets=campaign_ioc_sets)
                    if shared_count >= 3:
                        should_merge = True
                    else:
                        logger.info(
                            "Insufficient IOC overlap (%d) for brand-only match — cluster %s vs campaign %s (brand=%s)",
                            shared_count, cluster.id[:8], existing_brand_campaign.id[:8], brand,
                        )

                if should_merge:
                    # Link this cluster to the existing campaign.
                    try:
                        with session.begin_nested():
                            link = CampaignClusterModel(
                                campaign_id=existing_brand_campaign.id,
                                cluster_id=cluster.id,
                            )
                            session.add(link)
                            session.flush()
                    except Exception:
                        logger.debug(
                            "Cluster %s already linked to campaign %s",
                            cluster.id[:8], existing_brand_campaign.id[:8],
                        )
                    _recompute_domain_count(existing_brand_campaign, session)
                    existing_brand_campaign.last_seen = max(
                        existing_brand_campaign.last_seen or datetime.now(timezone.utc),
                        cluster.last_seen or datetime.now(timezone.utc),
                    )
                    # F-4: Update first_seen to earliest value.
                    existing_brand_campaign.first_seen = min(
                        existing_brand_campaign.first_seen or cluster.first_seen,
                        cluster.first_seen,
                    )
                    # Re-activate if dormant
                    if existing_brand_campaign.status == "dormant":
                        existing_brand_campaign.status = "active"
                        logger.info(
                            "Re-activated campaign %s (%s) for brand %s with new cluster",
                            existing_brand_campaign.id[:8], existing_brand_campaign.name, brand,
                        )
                    campaigns_updated += 1
                    cluster_processed = True
                    logger.debug(
                        "Linked cluster %s to existing campaign %s (brand=%s)",
                        cluster.id[:8], existing_brand_campaign.id[:8], brand,
                    )
                    continue
                # Not merging — fall through to create a new campaign.

            campaign_name = _generate_campaign_name(brand)
            campaign_id = str(uuid.uuid4())
            try:
                with session.begin_nested():
                    campaign = CampaignModel(
                        id=campaign_id,
                        name=campaign_name,
                        target_brand=brand,
                        first_seen=cluster.first_seen,
                        last_seen=cluster.last_seen,
                        domain_count=0,  # placeholder; recomputed below
                        kit_signature=cluster.signature_hash,
                        status="active",
                        meta={"source_cluster_type": cluster.cluster_type},
                    )
                    session.add(campaign)
                    session.flush()

                    # Link the cluster to the campaign.
                    link = CampaignClusterModel(
                        campaign_id=campaign.id,
                        cluster_id=cluster.id,
                    )
                    session.add(link)

                # Recompute domain_count from all linked clusters.
                _recompute_domain_count(campaign, session)

                campaigns_created += 1
                cluster_processed = True
                logger.info(
                    "Created campaign %s (%s): brand=%s, domain_count=%d",
                    campaign.id, campaign.name, brand, campaign.domain_count,
                )
            except Exception:
                # Concurrent insert — look up the campaign that was just created.
                campaign = (
                    session.query(CampaignModel)
                    .filter(CampaignModel.name == campaign_name)
                    .first()
                )
                if campaign is None:
                    logger.error(
                        "Campaign lookup failed after IntegrityError for name %s",
                        campaign_name,
                    )
                    continue
                # The campaign exists now — link the cluster to it.
                try:
                    with session.begin_nested():
                        link = CampaignClusterModel(
                            campaign_id=campaign.id,
                            cluster_id=cluster.id,
                        )
                        session.add(link)
                        session.flush()
                    _recompute_domain_count(campaign, session)
                    campaigns_updated += 1
                    cluster_processed = True
                except Exception:
                    logger.debug(
                        "Cluster %s already linked to campaign %s",
                        cluster.id[:8], campaign.id[:8],
                    )

        # Only update last_campaign_check for clusters that were actually processed
        if cluster_processed:
            cluster.last_campaign_check = datetime.now(timezone.utc)

    session.flush()
    logger.info(
        "Campaign detection complete: %d created, %d updated",
        campaigns_created, campaigns_updated,
    )
    return {"campaigns_created": campaigns_created, "campaigns_updated": campaigns_updated}


# ---------------------------------------------------------------------------
# Snapshot-level entry point
# ---------------------------------------------------------------------------


def detect_campaigns_for_snapshot(snapshot_id: str) -> int:
    """Run campaign detection triggered by a specific snapshot.

    Opens a DB session, verifies the snapshot exists, runs campaign detection
    on all qualifying clusters, and returns the total number of campaigns
    created or updated.  Exceptions are caught and logged so the caller never
    has to handle them.

    Args:
        snapshot_id: UUID of the snapshot that triggered this pipeline run.

    Returns:
        Total number of campaigns created/updated (0 if nothing happened or
        an error occurred).
    """
    try:
        from database import SnapshotModel, get_session  # type: ignore[import-untyped]

        with get_session() as session:
            # Verify the snapshot exists.
            snapshot = session.query(SnapshotModel).get(snapshot_id)
            if snapshot is None:
                logger.warning(
                    "detect_campaigns_for_snapshot: snapshot %s not found; skipping.",
                    snapshot_id,
                )
                return 0

            # Run campaign detection across all qualifying clusters.
            result = detect_campaigns(session)
            session.commit()

        total = result.get("campaigns_created", 0) + result.get("campaigns_updated", 0)
        logger.info(
            "detect_campaigns_for_snapshot(%s): %d campaigns created/updated",
            snapshot_id, total,
        )
        return total
    except Exception:
        logger.exception(
            "detect_campaigns_for_snapshot failed for snapshot_id=%s", snapshot_id,
        )
        return 0


# ---------------------------------------------------------------------------
# Read queries
# ---------------------------------------------------------------------------


def get_campaigns(session, status: Optional[str] = None) -> list[dict]:
    """List campaigns with optional status filter.

    Args:
        session: SQLAlchemy session.
        status: Optional status filter ("active", "dormant", "closed").

    Returns:
        List of campaign dicts sorted by last_seen descending.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignModel,
    )

    query = session.query(CampaignModel)
    if status is not None:
        query = query.filter(CampaignModel.status == status)

    campaigns = query.order_by(CampaignModel.last_seen.desc()).all()

    return [
        {
            "id": c.id,
            "name": c.name,
            "target_brand": c.target_brand,
            "first_seen": c.first_seen.isoformat() if c.first_seen else None,
            "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            "domain_count": c.domain_count,
            "kit_signature": c.kit_signature,
            "status": c.status,
            "meta": c.meta or {},
        }
        for c in campaigns
    ]


def get_campaign_details(campaign_id: str, session) -> Optional[dict]:
    """Return campaign details with all linked clusters and aggregated domain list.

    Args:
        campaign_id: UUID of the campaign.
        session: SQLAlchemy session.

    Returns:
        Dict with campaign info, linked clusters, and member domains,
        or None if the campaign is not found.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignClusterModel,
        CampaignModel,
        ClusterMemberModel,
        ClusterModel,
        DomainModel,
    )

    campaign = session.query(CampaignModel).get(campaign_id)
    if campaign is None:
        return None

    # Fetch linked clusters.
    cluster_links = (
        session.query(CampaignClusterModel)
        .filter(CampaignClusterModel.campaign_id == campaign_id)
        .all()
    )

    cluster_ids = [link.cluster_id for link in cluster_links]

    clusters_info = []
    all_domain_ids: set[str] = set()

    for cid in cluster_ids:
        cluster = session.query(ClusterModel).get(cid)
        if cluster is None:
            continue

        members = (
            session.query(ClusterMemberModel, DomainModel)
            .join(DomainModel, ClusterMemberModel.domain_id == DomainModel.id)
            .filter(ClusterMemberModel.cluster_id == cid)
            .all()
        )

        member_list = []
        for member, domain in members:
            all_domain_ids.add(domain.id)
            member_list.append({
                "domain_id": domain.id,
                "url": domain.url,
                "confidence": member.confidence,
                "joined_at": member.joined_at.isoformat() if member.joined_at else None,
            })

        clusters_info.append({
            "cluster_id": cluster.id,
            "cluster_type": cluster.cluster_type,
            "signature_hash": cluster.signature_hash,
            "description": cluster.description,
            "domain_count": cluster.domain_count,
            "first_seen": cluster.first_seen.isoformat() if cluster.first_seen else None,
            "last_seen": cluster.last_seen.isoformat() if cluster.last_seen else None,
            "members": member_list,
        })

    # Aggregate domain list (deduplicated across clusters).
    domain_rows = (
        session.query(DomainModel)
        .filter(DomainModel.id.in_(all_domain_ids))
        .all()
    )

    return {
        "id": campaign.id,
        "name": campaign.name,
        "target_brand": campaign.target_brand,
        "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
        "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        "domain_count": campaign.domain_count,
        "kit_signature": campaign.kit_signature,
        "status": campaign.status,
        "meta": campaign.meta or {},
        "clusters": clusters_info,
        "domains": [
            {"domain_id": d.id, "url": d.url}
            for d in domain_rows
        ],
    }


# ---------------------------------------------------------------------------
# Mutation
# ---------------------------------------------------------------------------


def update_campaign(campaign_id: str, updates: dict, session) -> Optional[dict]:
    """Update mutable fields on an existing campaign.

    Only ``name``, ``target_brand``, and ``status`` are accepted from the
    updates dict.  Unknown keys are silently ignored.

    Args:
        campaign_id: UUID of the campaign to update.
        updates: Dict with optional keys: name, target_brand, status.
        session: SQLAlchemy session (caller is responsible for commit).

    Returns:
        Updated campaign dict, or None if the campaign is not found.
    """
    from database import (  # type: ignore[import-untyped]
        CampaignModel,
    )

    campaign = session.query(CampaignModel).get(campaign_id)
    if campaign is None:
        return None

    allowed_fields = {"name", "target_brand", "status"}
    for field, value in updates.items():
        if field in allowed_fields:
            setattr(campaign, field, value)

    session.flush()

    logger.info(
        "Updated campaign %s: %s",
        campaign.id,
        {k: v for k, v in updates.items() if k in allowed_fields},
    )

    return {
        "id": campaign.id,
        "name": campaign.name,
        "target_brand": campaign.target_brand,
        "first_seen": campaign.first_seen.isoformat() if campaign.first_seen else None,
        "last_seen": campaign.last_seen.isoformat() if campaign.last_seen else None,
        "domain_count": campaign.domain_count,
        "kit_signature": campaign.kit_signature,
        "status": campaign.status,
        "meta": campaign.meta or {},
    }