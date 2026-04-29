"""VigilWolf v2 — Search and Pivot API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, or_
from sqlalchemy.orm import Session

from database import (
    DomainModel,
    SnapshotModel,
    RiskScoreModel,
    AnalysisResultModel,
    AlertModel,
    get_db,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class SearchResult(BaseModel):
    id: str
    url: str
    type: str  # "domain"
    risk_level: Optional[str] = None
    score: Optional[int] = None


class SearchResponse(BaseModel):
    results: list[SearchResult]
    total: int


class PivotSnapshot(BaseModel):
    id: str
    timestamp: Optional[str] = None
    trigger_type: str
    success: bool


class PivotAlert(BaseModel):
    id: int
    event_type: str
    severity: str
    status: str
    created_at: Optional[str] = None


class PivotAnalysisResult(BaseModel):
    plugin_name: str
    plugin_type: str
    score_contribution: int
    confidence: float
    tags: list


class PivotResponse(BaseModel):
    domain_id: str
    url: str
    snapshots: list[PivotSnapshot] = []
    alerts: list[PivotAlert] = []
    analysis_results: list[PivotAnalysisResult] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/search", )
def global_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> SearchResponse:
    """Global search: search domains by name, risk_level, brand."""
    # Search by domain URL
    domain_query = select(DomainModel).where(DomainModel.url.ilike(f"%{q}%"))
    domains = session.execute(domain_query.limit(limit)).scalars().all()

    results: list[SearchResult] = []
    for domain in domains:
        # Get latest risk score for ranking
        latest_snapshot = (
            session.execute(
                select(SnapshotModel)
                .where(SnapshotModel.domain_id == domain.id)
                .order_by(SnapshotModel.timestamp.desc())
                .limit(1)
            )
            .scalars()
            .first()
        )
        risk_level = None
        score = None
        if latest_snapshot:
            rs = (
                session.execute(
                    select(RiskScoreModel).where(RiskScoreModel.snapshot_id == latest_snapshot.id)
                )
                .scalars()
                .first()
            )
            if rs:
                risk_level = rs.risk_level
                score = rs.total_score

        results.append(SearchResult(
            id=domain.id,
            url=domain.url,
            type="domain",
            risk_level=risk_level,
            score=score,
        ))

    # Sort by score descending (None scores go last)
    results.sort(key=lambda r: r.score if r.score is not None else -1, reverse=True)

    return SearchResponse(results=results, total=len(results))


@router.get("/pivot/domain/{domain_id}", )
def pivot_domain(domain_id: str, session: Session = Depends(get_db)) -> PivotResponse:
    """Pivot from domain to related entities (snapshots, alerts, analysis results)."""
    domain = session.get(DomainModel, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Snapshots
    snapshot_rows = (
        session.execute(
            select(SnapshotModel)
            .where(SnapshotModel.domain_id == domain_id)
            .order_by(SnapshotModel.timestamp.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    snapshots = [
        PivotSnapshot(
            id=s.id,
            timestamp=s.timestamp.isoformat() if s.timestamp else None,
            trigger_type=s.trigger_type,
            success=s.success,
        )
        for s in snapshot_rows
    ]

    # Alerts
    alert_rows = (
        session.execute(
            select(AlertModel)
            .where(AlertModel.domain_id == domain_id)
            .order_by(AlertModel.created_at.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    alerts = [
        PivotAlert(
            id=a.id,
            event_type=a.event_type,
            severity=a.severity,
            status=a.status,
            created_at=a.created_at.isoformat() if a.created_at else None,
        )
        for a in alert_rows
    ]

    # Analysis results (from latest snapshot)
    analysis_results: list[PivotAnalysisResult] = []
    if snapshot_rows:
        latest_snapshot_id = snapshot_rows[0].id
        ar_rows = (
            session.execute(
                select(AnalysisResultModel)
                .where(AnalysisResultModel.snapshot_id == latest_snapshot_id)
            )
            .scalars()
            .all()
        )
        for ar in ar_rows:
            analysis_results.append(PivotAnalysisResult(
                plugin_name=ar.plugin_name,
                plugin_type=ar.plugin_type,
                score_contribution=ar.score_contribution,
                confidence=ar.confidence,
                tags=ar.tags if isinstance(ar.tags, list) else [],
            ))

    return PivotResponse(
        domain_id=domain.id,
        url=domain.url,
        snapshots=snapshots,
        alerts=alerts,
        analysis_results=analysis_results,
    )