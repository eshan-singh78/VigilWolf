"""VigilWolf v2 — Cluster API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from database import (
    ClusterModel,
    ClusterMemberModel,
    DomainModel,
    get_db,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ClusterListItem(BaseModel):
    id: str
    cluster_type: str
    signature_hash: str
    description: Optional[str] = None
    domain_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ClusterDetail(BaseModel):
    id: str
    cluster_type: str
    signature_hash: str
    signature_type: str
    description: Optional[str] = None
    domain_count: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    meta: dict = {}

    model_config = ConfigDict(from_attributes=True)


class DomainBriefWithScore(BaseModel):
    id: str
    url: str
    active: bool
    confidence: float = 1.0

    model_config = ConfigDict(from_attributes=True)


class ClustersListResponse(BaseModel):
    items: list[ClusterListItem]
    next_cursor: Optional[str] = None
    total: int


class ClusterDomainsResponse(BaseModel):
    items: list[DomainBriefWithScore]
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

@router.get("/clusters")
def list_clusters(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    cluster_type: Optional[str] = Query(None),
    session: Session = Depends(get_db),
) -> ClustersListResponse:
    """List clusters with cursor-based pagination and type filter."""
    query = select(ClusterModel)

    if cluster_type:
        query = query.where(ClusterModel.cluster_type == cluster_type)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination (cursor = cluster id as string)
    if cursor:
        query = query.where(ClusterModel.id > cursor)

    query = query.order_by(ClusterModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = [
        ClusterListItem(
            id=c.id,
            cluster_type=c.cluster_type,
            signature_hash=c.signature_hash,
            description=c.description,
            domain_count=c.domain_count,
            first_seen=_iso(c.first_seen),
            last_seen=_iso(c.last_seen),
        )
        for c in results[:limit]
    ]

    next_cursor = None
    if len(results) > limit:
        next_cursor = results[limit - 1].id

    return ClustersListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/clusters/{cluster_id}")
def get_cluster(cluster_id: str, session: Session = Depends(get_db)) -> ClusterDetail:
    """Get cluster detail."""
    cluster = session.get(ClusterModel, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    return ClusterDetail(
        id=cluster.id,
        cluster_type=cluster.cluster_type,
        signature_hash=cluster.signature_hash,
        signature_type=cluster.signature_type,
        description=cluster.description,
        domain_count=cluster.domain_count,
        first_seen=_iso(cluster.first_seen),
        last_seen=_iso(cluster.last_seen),
        meta=cluster.meta if isinstance(cluster.meta, dict) else {},
    )


@router.get("/clusters/{cluster_id}/domains")
def get_cluster_domains(
    cluster_id: str,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> ClusterDomainsResponse:
    """Get domains in a cluster with confidence scores."""
    cluster = session.get(ClusterModel, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Cluster not found")

    # Join cluster_members with domains
    query = (
        select(ClusterMemberModel, DomainModel)
        .join(DomainModel, DomainModel.id == ClusterMemberModel.domain_id)
        .where(ClusterMemberModel.cluster_id == cluster_id)
    )

    # Total count
    count_query = select(func.count()).select_from(
        select(ClusterMemberModel).where(
            ClusterMemberModel.cluster_id == cluster_id
        ).subquery()
    )
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination on member id
    if cursor:
        try:
            cursor_id = int(cursor)
            query = query.where(ClusterMemberModel.id > cursor_id)
        except ValueError:
            pass

    query = query.order_by(ClusterMemberModel.id).limit(limit + 1)
    rows = session.execute(query).all()

    items = [
        DomainBriefWithScore(
            id=domain.id,
            url=domain.url,
            active=domain.active,
            confidence=member.confidence,
        )
        for member, domain in rows[:limit]
    ]

    next_cursor = None
    if len(rows) > limit:
        next_cursor = str(rows[limit - 1][0].id)

    return ClusterDomainsResponse(items=items, next_cursor=next_cursor, total=total)