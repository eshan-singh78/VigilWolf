"""Campaign service for VigilWolf v2.

Auto-detects phishing campaigns from clusters and time windows.  Consumes
ClusterModel / ClusterMemberModel rows produced by the clustering service,
identifies coordinated activity targeting specific brands, and manages
CampaignModel / CampaignClusterModel rows for downstream consumption by the
alert and actor-profiling services.
"""
from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Brand detection
# ---------------------------------------------------------------------------

# Ordered by specificity — longer keywords first to avoid partial matches.
BRAND_KEYWORDS: list[tuple[str, str]] = [
    ("paypal", "PAYPAL"),
    ("wellsfargo", "WELLSFARGO"),
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
    """Attempt to identify the targeted brand from a list of domain URLs.

    Scans each URL (case-insensitive) for known brand keywords and returns
    the first match.  Returns None if no brand keyword is found.

    Args:
        domain_urls: List of domain URL strings to scan.

    Returns:
        Uppercased brand label (e.g. "PAYPAL"), or None.
    """
    combined = " ".join(domain_urls).lower()
    for keyword, brand in BRAND_KEYWORDS:
        # Match keyword as a word boundary to reduce false positives.
        if re.search(rf"\b{re.escape(keyword)}\b", combined):
            return brand
    return None


def _generate_campaign_name(brand: str) -> str:
    """Auto-generate a campaign name in the format BRAND_PHISH_MMDD.

    Uses the current UTC date for the MMDD suffix.

    Args:
        brand: Uppercased brand label.

    Returns:
        Campaign name string, e.g. "PAYPAL_PHISH_0428".
    """
    now = datetime.now(timezone.utc)
    date_suffix = now.strftime("%m%d")
    return f"{brand}_PHISH_{date_suffix}"


# ---------------------------------------------------------------------------
# Campaign detection
# ---------------------------------------------------------------------------


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

    # Find qualifying clusters: html_similarity, 3+ domains, within window.
    clusters = (
        session.query(ClusterModel)
        .filter(
            ClusterModel.cluster_type == "html_similarity",
            ClusterModel.domain_count >= 3,
            ClusterModel.last_seen >= cutoff,
        )
        .all()
    )

    campaigns_created = 0
    campaigns_updated = 0

    for cluster in clusters:
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

            campaign.domain_count = cluster.domain_count
            campaign.last_seen = cluster.last_seen

            # Determine dormancy: if the cluster has not seen new domains
            # recently, mark the campaign as dormant.
            dormant_cutoff = datetime.now(timezone.utc) - timedelta(days=DORMANT_THRESHOLD_DAYS)
            if cluster.last_seen < dormant_cutoff and campaign.status == "active":
                campaign.status = "dormant"
                logger.info(
                    "Campaign %s (%s) marked dormant — no new domains since %s",
                    campaign.id, campaign.name, cluster.last_seen.isoformat(),
                )

            campaigns_updated += 1
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
            campaign_name = _generate_campaign_name(brand)

            # Ensure name uniqueness — append a short suffix if collision.
            name = campaign_name
            suffix = 1
            while (
                session.query(CampaignModel)
                .filter(CampaignModel.name == name)
                .first()
                is not None
            ):
                name = f"{campaign_name}_{suffix}"
                suffix += 1

            campaign_id = str(uuid.uuid4())
            campaign = CampaignModel(
                id=campaign_id,
                name=name,
                target_brand=brand,
                first_seen=cluster.first_seen,
                last_seen=cluster.last_seen,
                domain_count=cluster.domain_count,
                kit_signature=cluster.signature_hash,
                status="active",
                meta={"source_cluster_type": cluster.cluster_type},
            )
            session.add(campaign)
            session.flush()  # ensure campaign.id is available

            # Link the cluster to the campaign.
            link = CampaignClusterModel(
                campaign_id=campaign.id,
                cluster_id=cluster.id,
            )
            session.add(link)

            campaigns_created += 1
            logger.info(
                "Created campaign %s (%s): brand=%s, domain_count=%d",
                campaign.id, campaign.name, brand, campaign.domain_count,
            )

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