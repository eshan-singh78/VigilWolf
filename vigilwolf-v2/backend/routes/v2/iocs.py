"""VigilWolf v2 — IOC (Indicator of Compromise) API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from database import (
    DomainModel,
    IocModel,
    IocOccurrenceModel,
    IocRelationshipModel,
    SnapshotModel,
    get_db,
)


def _escape_like(q: str) -> str:
    """Escape SQL LIKE wildcards (% and _) in user input."""
    return q.replace("%", "\\%").replace("_", "\\_")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class IocListItem(BaseModel):
    id: int
    type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    occurrence_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class IocOccurrenceBrief(BaseModel):
    id: int
    snapshot_id: str
    context: Optional[str] = None
    confidence: float = 1.0
    role: Optional[str] = None
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class IocRelationshipBrief(BaseModel):
    id: int
    source_ioc_id: int
    target_ioc_id: int
    relationship_type: str
    confidence: float = 1.0

    model_config = ConfigDict(from_attributes=True)


class IocDetail(BaseModel):
    id: int
    type: str
    value: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    occurrences: list[IocOccurrenceBrief] = []
    relationships: list[IocRelationshipBrief] = []

    model_config = ConfigDict(from_attributes=True)


class DomainBrief(BaseModel):
    id: str
    url: str
    active: bool

    model_config = ConfigDict(from_attributes=True)


class IocsListResponse(BaseModel):
    items: list[IocListItem]
    next_cursor: Optional[str] = None
    total: int


class DomainsListResponse(BaseModel):
    items: list[DomainBrief]
    next_cursor: Optional[str] = None
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(dt):
    """Format a datetime as ISO-8601, or return None."""
    return dt.isoformat() if dt else None


def _ioc_to_list_item(ioc: IocModel, session: Session) -> IocListItem:
    count = session.execute(
        select(func.count()).select_from(IocOccurrenceModel).where(
            IocOccurrenceModel.ioc_id == ioc.id
        )
    ).scalar() or 0

    return IocListItem(
        id=ioc.id,
        type=ioc.type,
        value=ioc.value,
        first_seen=_iso(ioc.first_seen),
        last_seen=_iso(ioc.last_seen),
        occurrence_count=count,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/iocs")
def list_iocs(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    type: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    session: Session = Depends(get_db),
) -> IocsListResponse:
    """List IOCs with cursor-based pagination, type filter, and search."""
    query = select(IocModel)

    if type:
        query = query.where(IocModel.type == type)
    if q:
        query = query.where(IocModel.value.ilike(f"%{_escape_like(q)}%", escape="\\"))

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination (cursor = last IOC id as string)
    if cursor:
        try:
            cursor_id = int(cursor)
            query = query.where(IocModel.id > cursor_id)
        except ValueError:
            pass

    query = query.order_by(IocModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = [_ioc_to_list_item(ioc, session) for ioc in results[:limit]]

    next_cursor = None
    if len(results) > limit:
        next_cursor = str(results[limit - 1].id)

    return IocsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: int, session: Session = Depends(get_db)) -> IocDetail:
    """Get IOC detail with occurrences and relationships."""
    ioc = session.get(IocModel, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    occ_rows = (
        session.execute(
            select(IocOccurrenceModel).where(IocOccurrenceModel.ioc_id == ioc.id)
        )
        .scalars()
        .all()
    )
    occurrences = [
        IocOccurrenceBrief(
            id=o.id,
            snapshot_id=o.snapshot_id,
            context=o.context,
            confidence=o.confidence,
            role=o.role,
            created_at=_iso(o.created_at),
        )
        for o in occ_rows
    ]

    rel_rows = (
        session.execute(
            select(IocRelationshipModel).where(
                (IocRelationshipModel.source_ioc_id == ioc.id)
                | (IocRelationshipModel.target_ioc_id == ioc.id)
            )
        )
        .scalars()
        .all()
    )
    relationships = [
        IocRelationshipBrief(
            id=r.id,
            source_ioc_id=r.source_ioc_id,
            target_ioc_id=r.target_ioc_id,
            relationship_type=r.relationship_type,
            confidence=r.confidence,
        )
        for r in rel_rows
    ]

    return IocDetail(
        id=ioc.id,
        type=ioc.type,
        value=ioc.value,
        first_seen=_iso(ioc.first_seen),
        last_seen=_iso(ioc.last_seen),
        occurrences=occurrences,
        relationships=relationships,
    )


@router.get("/iocs/{ioc_id}/domains")
def get_ioc_domains(
    ioc_id: int,
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> DomainsListResponse:
    """Get domains containing this IOC, via occurrence snapshots."""
    ioc = session.get(IocModel, ioc_id)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Find snapshot IDs where this IOC appears, then resolve their domains
    snapshot_ids = (
        session.execute(
            select(IocOccurrenceModel.snapshot_id).where(
                IocOccurrenceModel.ioc_id == ioc_id
            )
        )
        .scalars()
        .all()
    )

    if not snapshot_ids:
        return DomainsListResponse(items=[], next_cursor=None, total=0)

    # Resolve domain IDs from snapshots, then load domains
    domain_ids = (
        session.execute(
            select(SnapshotModel.domain_id).where(SnapshotModel.id.in_(snapshot_ids))
        )
        .scalars()
        .all()
    )

    if not domain_ids:
        return DomainsListResponse(items=[], next_cursor=None, total=0)

    # Deduplicate domain IDs
    unique_domain_ids = list(dict.fromkeys(domain_ids))

    query = select(DomainModel).where(DomainModel.id.in_(unique_domain_ids))

    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    if cursor:
        query = query.where(DomainModel.id > cursor)

    query = query.order_by(DomainModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = [
        DomainBrief(id=d.id, url=d.url, active=d.active)
        for d in results[:limit]
    ]

    next_cursor = None
    if len(results) > limit:
        next_cursor = results[limit - 1].id

    return DomainsListResponse(items=items, next_cursor=next_cursor, total=total)