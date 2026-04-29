"""VigilWolf v2 — Campaign API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from database import (
    CampaignModel,
    CampaignClusterModel,
    ClusterModel,
    ClusterMemberModel,
    DomainModel,
    get_db,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class CampaignListItem(BaseModel):
    id: str
    name: str
    target_brand: Optional[str] = None
    status: str = "active"
    domain_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ClusterBrief(BaseModel):
    id: str
    cluster_type: str
    signature_hash: str
    description: Optional[str] = None
    domain_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class CampaignDetail(BaseModel):
    id: str
    name: str
    target_brand: Optional[str] = None
    status: str = "active"
    domain_count: int = 0
    kit_signature: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    meta: dict = {}
    clusters: list[ClusterBrief] = []

    model_config = ConfigDict(from_attributes=True)


class CampaignUpdateBody(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    target_brand: Optional[str] = None


class DomainBrief(BaseModel):
    id: str
    url: str
    active: bool

    model_config = ConfigDict(from_attributes=True)


class CampaignsListResponse(BaseModel):
    items: list[CampaignListItem]
    next_cursor: Optional[str] = None
    total: int


class CampaignDomainsResponse(BaseModel):
    items: list[DomainBrief]
    next_cursor: Optional[str] = None
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt):
    """Format a datetime as ISO-8601, or return None."""
    return dt.isoformat() if dt else None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/campaigns")
def list_campaigns(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None),
    session: Session = Depends(get_db),
) -> CampaignsListResponse:
    """List campaigns with cursor-based pagination and status filter."""
    query = select(CampaignModel)

    if status:
        query = query.where(CampaignModel.status == status)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination (cursor = campaign id)
    if cursor:
        query = query.where(CampaignModel.id > cursor)

    query = query.order_by(CampaignModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = [
        CampaignListItem(
            id=c.id,
            name=c.name,
            target_brand=c.target_brand,
            status=c.status,
            domain_count=c.domain_count,
            first_seen=_iso(c.first_seen),
            last_seen=_iso(c.last_seen),
        )
        for c in results[:limit]
    ]

    next_cursor = None
    if len(results) > limit:
        next_cursor = results[limit - 1].id

    return CampaignsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: str, session: Session = Depends(get_db)) -> CampaignDetail:
    """Get campaign detail with clusters."""
    campaign = session.get(CampaignModel, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Fetch linked clusters
    cc_rows = (
        session.execute(
            select(CampaignClusterModel).where(
                CampaignClusterModel.campaign_id == campaign_id
            )
        )
        .scalars()
        .all()
    )
    cluster_ids = [cc.cluster_id for cc in cc_rows]

    clusters: list[ClusterBrief] = []
    if cluster_ids:
        cluster_rows = (
            session.execute(
                select(ClusterModel).where(ClusterModel.id.in_(cluster_ids))
            )
            .scalars()
            .all()
        )
        clusters = [
            ClusterBrief(
                id=cl.id,
                cluster_type=cl.cluster_type,
                signature_hash=cl.signature_hash,
                description=cl.description,
                domain_count=cl.domain_count,
            )
            for cl in cluster_rows
        ]

    return CampaignDetail(
        id=campaign.id,
        name=campaign.name,
        target_brand=campaign.target_brand,
        status=campaign.status,
        domain_count=campaign.domain_count,
        kit_signature=campaign.kit_signature,
        first_seen=_iso(campaign.first_seen),
        last_seen=_iso(campaign.last_seen),
        meta=campaign.meta if isinstance(campaign.meta, dict) else {},
        clusters=clusters,
    )


@router.put("/campaigns/{campaign_id}")
def update_campaign(
    campaign_id: str,
    body: CampaignUpdateBody,
    session: Session = Depends(get_db),
) -> CampaignDetail:
    """Update campaign name, status, or target_brand."""
    campaign = session.get(CampaignModel, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if body.name is not None:
        campaign.name = body.name
    if body.status is not None:
        campaign.status = body.status
    if body.target_brand is not None:
        campaign.target_brand = body.target_brand

    session.commit()
    session.refresh(campaign)

    # Fetch linked clusters for response
    cc_rows = (
        session.execute(
            select(CampaignClusterModel).where(
                CampaignClusterModel.campaign_id == campaign_id
            )
        )
        .scalars()
        .all()
    )
    cluster_ids = [cc.cluster_id for cc in cc_rows]

    clusters: list[ClusterBrief] = []
    if cluster_ids:
        cluster_rows = (
            session.execute(
                select(ClusterModel).where(ClusterModel.id.in_(cluster_ids))
            )
            .scalars()
            .all()
        )
        clusters = [
            ClusterBrief(
                id=cl.id,
                cluster_type=cl.cluster_type,
                signature_hash=cl.signature_hash,
                description=cl.description,
                domain_count=cl.domain_count,
            )
            for cl in cluster_rows
        ]

    return CampaignDetail(
        id=campaign.id,
        name=campaign.name,
        target_brand=campaign.target_brand,
        status=campaign.status,
        domain_count=campaign.domain_count,
        kit_signature=campaign.kit_signature,
        first_seen=_iso(campaign.first_seen),
        last_seen=_iso(campaign.last_seen),
        meta=campaign.meta if isinstance(campaign.meta, dict) else {},
        clusters=clusters,
    )


@router.get("/campaigns/{campaign_id}/domains")
def get_campaign_domains(
    campaign_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> CampaignDomainsResponse:
    """Get domains in a campaign (via clusters)."""
    campaign = session.get(CampaignModel, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Get cluster IDs for this campaign
    cc_rows = (
        session.execute(
            select(CampaignClusterModel.cluster_id).where(
                CampaignClusterModel.campaign_id == campaign_id
            )
        )
        .scalars()
        .all()
    )

    if not cc_rows:
        return CampaignDomainsResponse(items=[], next_cursor=None, total=0)

    # Get domain IDs via cluster memberships
    member_query = (
        select(ClusterMemberModel.domain_id)
        .where(ClusterMemberModel.cluster_id.in_(cc_rows))
    )

    # Cursor pagination on domain id
    if cursor:
        member_query = member_query.where(ClusterMemberModel.domain_id > cursor)

    # Count total unique domains
    count_query = select(func.count()).select_from(
        select(ClusterMemberModel.domain_id)
        .where(ClusterMemberModel.cluster_id.in_(cc_rows))
        .subquery()
    )
    total = session.execute(count_query).scalar() or 0

    # Fetch paginated domain IDs
    domain_id_query = (
        select(ClusterMemberModel.domain_id)
        .where(ClusterMemberModel.cluster_id.in_(cc_rows))
        .order_by(ClusterMemberModel.domain_id)
        .limit(limit + 1)
    )
    if cursor:
        domain_id_query = domain_id_query.where(ClusterMemberModel.domain_id > cursor)

    domain_ids = session.execute(domain_id_query).scalars().all()

    # Deduplicate domain IDs (a domain may belong to multiple clusters)
    seen: set[str] = set()
    unique_ids: list[str] = []
    for did in domain_ids:
        if did not in seen:
            seen.add(did)
            unique_ids.append(did)

    has_more = len(unique_ids) > limit
    unique_ids = unique_ids[:limit]

    if not unique_ids:
        return CampaignDomainsResponse(items=[], next_cursor=None, total=total)

    domain_rows = (
        session.execute(
            select(DomainModel).where(DomainModel.id.in_(unique_ids))
        )
        .scalars()
        .all()
    )
    # Preserve order by unique_ids
    domain_map = {d.id: d for d in domain_rows}
    items = [
        DomainBrief(
            id=domain_map[did].id,
            url=domain_map[did].url,
            active=domain_map[did].active,
        )
        for did in unique_ids
        if did in domain_map
    ]

    next_cursor = None
    if has_more:
        next_cursor = unique_ids[-1]

    return CampaignDomainsResponse(items=items, next_cursor=next_cursor, total=total)