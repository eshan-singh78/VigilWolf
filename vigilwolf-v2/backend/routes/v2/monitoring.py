"""VigilWolf v2 — Monitoring API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, func
from sqlalchemy.orm import Session

import config
from database import GroupModel, DomainModel, get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class SystemStatus(BaseModel):
    status: str
    version: str
    environment: str
    pipeline_enabled: bool
    clustering_enabled: bool
    alerts_enabled: bool
    total_domains: int
    total_groups: int


class GroupResponse(BaseModel):
    id: str
    name: str
    created_at: Optional[str] = None
    domain_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class DomainBrief(BaseModel):
    id: str
    url: str
    active: bool


class GroupCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None


class GroupUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class AddDomainRequest(BaseModel):
    """Request body for adding a domain to a monitoring group."""
    domain: str = Field(..., min_length=1, max_length=253)
    frequency_seconds: int = Field(3600, ge=60, le=86400)


class AddDomainResponse(BaseModel):
    """Response after adding a domain to a group."""
    id: str
    url: str
    group_id: str
    frequency_seconds: int
    active: bool
    created: bool  # True if the domain was newly created, False if it already existed


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/monitoring/status", )
def system_status(session: Session = Depends(get_db)) -> SystemStatus:
    """System status: pipeline status, domain/group counts, etc."""
    total_domains = session.execute(
        select(func.count()).select_from(DomainModel)
    ).scalar() or 0

    total_groups = session.execute(
        select(func.count()).select_from(GroupModel)
    ).scalar() or 0

    return SystemStatus(
        status="ok",
        version="2.0.0",
        environment=config.ENVIRONMENT,
        pipeline_enabled=config.USE_DRAMATIQ_PIPELINE,
        clustering_enabled=config.CLUSTERING_ENABLED,
        alerts_enabled=config.ALERTS_ENABLED,
        total_domains=total_domains,
        total_groups=total_groups,
    )


@router.get("/monitoring/groups", )
def list_groups(session: Session = Depends(get_db)) -> list[GroupResponse]:
    """List monitoring groups."""
    groups = session.execute(select(GroupModel)).scalars().all()

    result = []
    for g in groups:
        domain_count = session.execute(
            select(func.count()).select_from(DomainModel).where(DomainModel.group_id == g.id)
        ).scalar() or 0

        result.append(GroupResponse(
            id=g.id,
            name=g.name,
            created_at=g.created_at.isoformat() if g.created_at else None,
            domain_count=domain_count,
        ))

    return result


@router.post("/monitoring/groups", status_code=201)
def create_group(
    body: GroupCreateRequest,
    session: Session = Depends(get_db),
) -> GroupResponse:
    """Create a monitoring group."""
    group = GroupModel(name=body.name)
    session.add(group)
    session.commit()
    session.refresh(group)
    return GroupResponse(
        id=group.id,
        name=group.name,
        created_at=group.created_at.isoformat() if group.created_at else None,
        domain_count=0,
    )


@router.patch("/monitoring/groups/{group_id}")
def update_group(
    group_id: str,
    body: GroupUpdateRequest,
    session: Session = Depends(get_db),
) -> GroupResponse:
    """Update group metadata."""
    group = session.get(GroupModel, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    if body.name is not None:
        group.name = body.name
    session.commit()
    session.refresh(group)
    domain_count = session.execute(
        select(func.count()).select_from(DomainModel).where(DomainModel.group_id == group.id)
    ).scalar() or 0
    return GroupResponse(
        id=group.id,
        name=group.name,
        created_at=group.created_at.isoformat() if group.created_at else None,
        domain_count=domain_count,
    )


@router.delete("/monitoring/groups/{group_id}")
def delete_group(group_id: str, session: Session = Depends(get_db)) -> dict:
    """Delete a monitoring group."""
    group = session.get(GroupModel, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    session.delete(group)
    session.commit()
    return {"deleted": True, "group_id": group_id}


@router.get("/monitoring/groups/{group_id}/domains", )
def list_group_domains(group_id: str, session: Session = Depends(get_db)) -> list[DomainBrief]:
    """List domains in a monitoring group."""
    group = session.get(GroupModel, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    domains = session.execute(
        select(DomainModel).where(DomainModel.group_id == group_id)
    ).scalars().all()

    return [
        DomainBrief(id=d.id, url=d.url, active=d.active)
        for d in domains
    ]


@router.post("/monitoring/groups/{group_id}/domains", status_code=201)
def add_domain_to_group(
    group_id: str,
    body: AddDomainRequest,
    session: Session = Depends(get_db),
) -> AddDomainResponse:
    """Add a domain to a monitoring group.

    If the domain already exists in the group, it is returned without
    duplication.  If the domain exists in another group, a new DomainModel
    entry is created in the target group.
    """
    group = session.get(GroupModel, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Check if the domain already exists in this group
    existing = session.execute(
        select(DomainModel).where(
            DomainModel.group_id == group_id,
            DomainModel.url == body.domain,
        )
    ).scalar_one_or_none()

    if existing:
        return AddDomainResponse(
            id=existing.id,
            url=existing.url,
            group_id=existing.group_id,
            frequency_seconds=existing.frequency_seconds,
            active=existing.active,
            created=False,
        )

    # Create a new domain entry in the group
    new_domain = DomainModel(
        group_id=group_id,
        url=body.domain,
        frequency_seconds=body.frequency_seconds,
        active=True,
    )
    session.add(new_domain)
    session.commit()
    session.refresh(new_domain)

    return AddDomainResponse(
        id=new_domain.id,
        url=new_domain.url,
        group_id=new_domain.group_id,
        frequency_seconds=new_domain.frequency_seconds,
        active=new_domain.active,
        created=True,
    )


@router.delete("/monitoring/groups/{group_id}/domains/{domain_id}")
def remove_domain_from_group(
    group_id: str,
    domain_id: str,
    session: Session = Depends(get_db),
) -> dict:
    """Remove a domain from a monitoring group."""
    group = session.get(GroupModel, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    domain = session.get(DomainModel, domain_id)
    if not domain or domain.group_id != group_id:
        raise HTTPException(status_code=404, detail="Domain not found in this group")

    session.delete(domain)
    session.commit()

    return {"deleted": True, "domain_id": domain_id, "group_id": group_id}


@router.get("/monitoring/pipeline")
async def get_pipeline_stats() -> dict:
    """Return real-time pipeline health metrics."""
    from services.pipeline_metrics import pipeline_metrics
    return pipeline_metrics.get_stats()