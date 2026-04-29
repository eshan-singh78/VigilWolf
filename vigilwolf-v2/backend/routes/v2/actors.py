"""VigilWolf v2 — Actor API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from database import (
    ActorModel,
    ActorCampaignModel,
    CampaignModel,
    get_db,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ActorListItem(BaseModel):
    id: str
    label: str
    confidence_score: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    campaign_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class CampaignBrief(BaseModel):
    id: str
    name: str
    target_brand: Optional[str] = None
    status: str = "active"
    domain_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class ActorDetail(BaseModel):
    id: str
    label: str
    fingerprint: dict = {}
    confidence_score: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    meta: dict = {}
    campaigns: list[CampaignBrief] = []

    model_config = ConfigDict(from_attributes=True)


class ActorUpdateBody(BaseModel):
    label: Optional[str] = None


class ActorsListResponse(BaseModel):
    items: list[ActorListItem]
    next_cursor: Optional[str] = None
    total: int


class ActorCampaignsResponse(BaseModel):
    items: list[CampaignBrief]
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

@router.get("/actors")
def list_actors(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> ActorsListResponse:
    """List actors with cursor-based pagination."""
    query = select(ActorModel)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination (cursor = actor id)
    if cursor:
        query = query.where(ActorModel.id > cursor)

    query = query.order_by(ActorModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = []
    for a in results[:limit]:
        # Count campaigns for this actor
        campaign_count = session.execute(
            select(func.count()).select_from(
                select(ActorCampaignModel).where(
                    ActorCampaignModel.actor_id == a.id
                ).subquery()
            )
        ).scalar() or 0

        items.append(
            ActorListItem(
                id=a.id,
                label=a.label,
                confidence_score=a.confidence_score,
                first_seen=_iso(a.first_seen),
                last_seen=_iso(a.last_seen),
                campaign_count=campaign_count,
            )
        )

    next_cursor = None
    if len(results) > limit:
        next_cursor = results[limit - 1].id

    return ActorsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/actors/{actor_id}")
def get_actor(actor_id: str, session: Session = Depends(get_db)) -> ActorDetail:
    """Get actor detail with campaigns and fingerprint."""
    actor = session.get(ActorModel, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    # Fetch linked campaigns
    ac_rows = (
        session.execute(
            select(ActorCampaignModel).where(
                ActorCampaignModel.actor_id == actor_id
            )
        )
        .scalars()
        .all()
    )
    campaign_ids = [ac.campaign_id for ac in ac_rows]

    campaigns: list[CampaignBrief] = []
    if campaign_ids:
        campaign_rows = (
            session.execute(
                select(CampaignModel).where(CampaignModel.id.in_(campaign_ids))
            )
            .scalars()
            .all()
        )
        campaigns = [
            CampaignBrief(
                id=c.id,
                name=c.name,
                target_brand=c.target_brand,
                status=c.status,
                domain_count=c.domain_count,
            )
            for c in campaign_rows
        ]

    return ActorDetail(
        id=actor.id,
        label=actor.label,
        fingerprint=actor.fingerprint if isinstance(actor.fingerprint, dict) else {},
        confidence_score=actor.confidence_score,
        first_seen=_iso(actor.first_seen),
        last_seen=_iso(actor.last_seen),
        meta=actor.meta if isinstance(actor.meta, dict) else {},
        campaigns=campaigns,
    )


@router.put("/actors/{actor_id}")
def update_actor(
    actor_id: str,
    body: ActorUpdateBody,
    session: Session = Depends(get_db),
) -> ActorDetail:
    """Update actor label."""
    actor = session.get(ActorModel, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    if body.label is not None:
        actor.label = body.label

    session.commit()
    session.refresh(actor)

    # Fetch linked campaigns for response
    ac_rows = (
        session.execute(
            select(ActorCampaignModel).where(
                ActorCampaignModel.actor_id == actor_id
            )
        )
        .scalars()
        .all()
    )
    campaign_ids = [ac.campaign_id for ac in ac_rows]

    campaigns: list[CampaignBrief] = []
    if campaign_ids:
        campaign_rows = (
            session.execute(
                select(CampaignModel).where(CampaignModel.id.in_(campaign_ids))
            )
            .scalars()
            .all()
        )
        campaigns = [
            CampaignBrief(
                id=c.id,
                name=c.name,
                target_brand=c.target_brand,
                status=c.status,
                domain_count=c.domain_count,
            )
            for c in campaign_rows
        ]

    return ActorDetail(
        id=actor.id,
        label=actor.label,
        fingerprint=actor.fingerprint if isinstance(actor.fingerprint, dict) else {},
        confidence_score=actor.confidence_score,
        first_seen=_iso(actor.first_seen),
        last_seen=_iso(actor.last_seen),
        meta=actor.meta if isinstance(actor.meta, dict) else {},
        campaigns=campaigns,
    )


@router.get("/actors/{actor_id}/campaigns")
def get_actor_campaigns(
    actor_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> ActorCampaignsResponse:
    """Get campaigns linked to an actor."""
    actor = session.get(ActorModel, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")

    # Get campaign IDs for this actor
    ac_query = select(ActorCampaignModel.campaign_id).where(
        ActorCampaignModel.actor_id == actor_id
    )

    # Total count
    count_query = select(func.count()).select_from(
        select(ActorCampaignModel).where(
            ActorCampaignModel.actor_id == actor_id
        ).subquery()
    )
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination on campaign id
    if cursor:
        ac_query = ac_query.where(ActorCampaignModel.campaign_id > cursor)

    ac_query = ac_query.order_by(ActorCampaignModel.campaign_id).limit(limit + 1)
    campaign_ids = session.execute(ac_query).scalars().all()

    has_more = len(campaign_ids) > limit
    campaign_ids = campaign_ids[:limit]

    if not campaign_ids:
        return ActorCampaignsResponse(items=[], next_cursor=None, total=total)

    campaign_rows = (
        session.execute(
            select(CampaignModel).where(CampaignModel.id.in_(campaign_ids))
        )
        .scalars()
        .all()
    )
    # Preserve order by campaign_ids
    campaign_map = {c.id: c for c in campaign_rows}
    items = [
        CampaignBrief(
            id=campaign_map[cid].id,
            name=campaign_map[cid].name,
            target_brand=campaign_map[cid].target_brand,
            status=campaign_map[cid].status,
            domain_count=campaign_map[cid].domain_count,
        )
        for cid in campaign_ids
        if cid in campaign_map
    ]

    next_cursor = None
    if has_more:
        next_cursor = campaign_ids[-1]

    return ActorCampaignsResponse(items=items, next_cursor=next_cursor, total=total)