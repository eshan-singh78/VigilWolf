"""VigilWolf v2 — Domain and Threat API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func, and_, exists
from sqlalchemy.orm import Session, aliased

from database import (
    DomainModel,
    RiskScoreModel,
    SnapshotModel,
    AnalysisResultModel,
    SnapshotPluginStatusModel,
    get_db,
)


def _escape_like(q: str) -> str:
    """Escape SQL LIKE wildcards (% and _) in user input."""
    return q.replace("%", "\\%").replace("_", "\\_")

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class RiskScoreBrief(BaseModel):
    total_score: int
    normalized_score: float
    risk_level: str
    severity: str
    reasons: list
    dominant_signals: list
    overall_confidence: float

    model_config = ConfigDict(from_attributes=True)


class DomainListItem(BaseModel):
    id: str
    group_id: str
    url: str
    active: bool
    risk_level: Optional[str] = None
    risk_score: Optional[RiskScoreBrief] = None

    model_config = ConfigDict(from_attributes=True)


class DomainDetail(BaseModel):
    id: str
    group_id: str
    url: str
    dump_mode: str
    frequency_seconds: int
    active: bool
    risk_score: Optional[RiskScoreBrief] = None

    model_config = ConfigDict(from_attributes=True)


class PluginStatusBrief(BaseModel):
    plugin_name: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    error_message: Optional[str] = None


class AnalysisResultBrief(BaseModel):
    plugin_name: str
    plugin_version: str
    plugin_type: str
    score_contribution: int
    confidence: float
    tags: list
    findings: dict


class ThreatView(BaseModel):
    domain: DomainDetail
    risk_score: Optional[RiskScoreBrief] = None
    analysis_results: list[AnalysisResultBrief] = []
    plugin_statuses: list[PluginStatusBrief] = []


class ThreatStatsResponse(BaseModel):
    total: int
    high: int
    medium: int
    low: int


class DomainsListResponse(BaseModel):
    items: list[DomainListItem]
    next_cursor: Optional[str] = None
    total: int


def _risk_brief(rs: RiskScoreModel | None) -> Optional[RiskScoreBrief]:
    if not rs:
        return None
    return RiskScoreBrief(
        total_score=rs.total_score,
        normalized_score=rs.normalized_score,
        risk_level=rs.risk_level,
        severity=rs.severity,
        reasons=rs.reasons if isinstance(rs.reasons, list) else [],
        dominant_signals=rs.dominant_signals if isinstance(rs.dominant_signals, list) else [],
        overall_confidence=rs.overall_confidence,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/domains", )
def list_domains(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    risk_level: Optional[str] = Query(None),
    brand: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    session: Session = Depends(get_db),
) -> DomainsListResponse:
    """List domains with cursor-based pagination and filters."""
    latest_ts_subq = (
        select(
            SnapshotModel.domain_id.label("domain_id"),
            func.max(SnapshotModel.timestamp).label("latest_ts"),
        )
        .group_by(SnapshotModel.domain_id)
        .subquery()
    )
    latest_snapshot = aliased(SnapshotModel)

    query = (
        select(DomainModel, RiskScoreModel)
        .outerjoin(latest_ts_subq, latest_ts_subq.c.domain_id == DomainModel.id)
        .outerjoin(
            latest_snapshot,
            and_(
                latest_snapshot.domain_id == DomainModel.id,
                latest_snapshot.timestamp == latest_ts_subq.c.latest_ts,
            ),
        )
        .outerjoin(RiskScoreModel, RiskScoreModel.snapshot_id == latest_snapshot.id)
    )

    if q:
        query = query.where(DomainModel.url.ilike(f"%{_escape_like(q)}%", escape="\\"))
    if cursor:
        query = query.where(DomainModel.id > cursor)
    if risk_level:
        query = query.where(RiskScoreModel.risk_level == risk_level)
    if brand:
        brand_exists = exists(
            select(1).where(
                AnalysisResultModel.snapshot_id == latest_snapshot.id,
                AnalysisResultModel.tags.contains([brand]),
            )
        )
        query = query.where(brand_exists)

    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0
    rows = session.execute(query.order_by(DomainModel.id).limit(limit + 1)).all()
    page_rows = rows[:limit]

    items: list[DomainListItem] = []
    for domain, rs in page_rows:
        items.append(
            DomainListItem(
                id=domain.id,
                group_id=domain.group_id,
                url=domain.url,
                active=domain.active,
                risk_level=rs.risk_level if rs else None,
                risk_score=_risk_brief(rs),
            )
        )

    # Next cursor
    next_cursor = None
    if len(rows) > limit:
        next_cursor = page_rows[-1][0].id

    return DomainsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/domains/{domain_id}", )
def get_domain(domain_id: str, session: Session = Depends(get_db)) -> DomainDetail:
    """Get domain detail with latest risk score."""
    domain = session.get(DomainModel, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    detail = DomainDetail(
        id=domain.id,
        group_id=domain.group_id,
        url=domain.url,
        dump_mode=domain.dump_mode,
        frequency_seconds=domain.frequency_seconds,
        active=domain.active,
    )

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
    if latest_snapshot:
        rs = (
            session.execute(
                select(RiskScoreModel).where(RiskScoreModel.snapshot_id == latest_snapshot.id)
            )
            .scalars()
            .first()
        )
        if rs:
            detail.risk_score = RiskScoreBrief(
                total_score=rs.total_score,
                normalized_score=rs.normalized_score,
                risk_level=rs.risk_level,
                severity=rs.severity,
                reasons=rs.reasons if isinstance(rs.reasons, list) else [],
                dominant_signals=rs.dominant_signals if isinstance(rs.dominant_signals, list) else [],
                overall_confidence=rs.overall_confidence,
            )

    return detail


@router.get("/domains/{domain_id}/threat", )
def get_domain_threat(domain_id: str, session: Session = Depends(get_db)) -> ThreatView:
    """Threat view: domain + risk_score + analysis results + plugin statuses."""
    domain = session.get(DomainModel, domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    detail = DomainDetail(
        id=domain.id,
        group_id=domain.group_id,
        url=domain.url,
        dump_mode=domain.dump_mode,
        frequency_seconds=domain.frequency_seconds,
        active=domain.active,
    )

    risk_score_brief: Optional[RiskScoreBrief] = None
    analysis_results: list[AnalysisResultBrief] = []
    plugin_statuses: list[PluginStatusBrief] = []

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

    if latest_snapshot:
        rs = (
            session.execute(
                select(RiskScoreModel).where(RiskScoreModel.snapshot_id == latest_snapshot.id)
            )
            .scalars()
            .first()
        )
        if rs:
            risk_score_brief = RiskScoreBrief(
                total_score=rs.total_score,
                normalized_score=rs.normalized_score,
                risk_level=rs.risk_level,
                severity=rs.severity,
                reasons=rs.reasons if isinstance(rs.reasons, list) else [],
                dominant_signals=rs.dominant_signals if isinstance(rs.dominant_signals, list) else [],
                overall_confidence=rs.overall_confidence,
            )

        # Analysis results
        ar_rows = (
            session.execute(
                select(AnalysisResultModel)
                .where(AnalysisResultModel.snapshot_id == latest_snapshot.id)
            )
            .scalars()
            .all()
        )
        for ar in ar_rows:
            analysis_results.append(AnalysisResultBrief(
                plugin_name=ar.plugin_name,
                plugin_version=ar.plugin_version,
                plugin_type=ar.plugin_type,
                score_contribution=ar.score_contribution,
                confidence=ar.confidence,
                tags=ar.tags if isinstance(ar.tags, list) else [],
                findings=ar.result_json if isinstance(ar.result_json, dict) else {},
            ))

        # Plugin statuses
        ps_rows = (
            session.execute(
                select(SnapshotPluginStatusModel)
                .where(SnapshotPluginStatusModel.snapshot_id == latest_snapshot.id)
            )
            .scalars()
            .all()
        )
        for ps in ps_rows:
            plugin_statuses.append(PluginStatusBrief(
                plugin_name=ps.plugin_name,
                status=ps.status,
                started_at=ps.started_at.isoformat() if ps.started_at else None,
                completed_at=ps.completed_at.isoformat() if ps.completed_at else None,
                error_message=ps.error_message,
            ))

    return ThreatView(
        domain=detail,
        risk_score=risk_score_brief,
        analysis_results=analysis_results,
        plugin_statuses=plugin_statuses,
    )


@router.get("/threats", )
def list_threats(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_db),
) -> DomainsListResponse:
    """Threat feed: domains with risk_level high or medium."""
    latest_ts_subq = (
        select(
            SnapshotModel.domain_id.label("domain_id"),
            func.max(SnapshotModel.timestamp).label("latest_ts"),
        )
        .group_by(SnapshotModel.domain_id)
        .subquery()
    )
    latest_snapshot = aliased(SnapshotModel)

    query = (
        select(DomainModel, RiskScoreModel)
        .join(latest_ts_subq, latest_ts_subq.c.domain_id == DomainModel.id)
        .join(
            latest_snapshot,
            and_(
                latest_snapshot.domain_id == DomainModel.id,
                latest_snapshot.timestamp == latest_ts_subq.c.latest_ts,
            ),
        )
        .join(RiskScoreModel, RiskScoreModel.snapshot_id == latest_snapshot.id)
        .where(RiskScoreModel.risk_level.in_(["high", "medium"]))
    )
    if cursor:
        query = query.where(DomainModel.id > cursor)

    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0
    rows = session.execute(query.order_by(DomainModel.id).limit(limit + 1)).all()
    page_rows = rows[:limit]

    items: list[DomainListItem] = []
    for domain, rs in page_rows:
        items.append(
            DomainListItem(
                id=domain.id,
                group_id=domain.group_id,
                url=domain.url,
                active=domain.active,
                risk_level=rs.risk_level,
                risk_score=_risk_brief(rs),
            )
        )

    next_cursor = None
    if len(rows) > limit:
        next_cursor = page_rows[-1][0].id

    return DomainsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/threats/stats", )
def threat_stats(session: Session = Depends(get_db)) -> ThreatStatsResponse:
    """Counts: total, high, medium, low.

    Counts risk levels across all domains. For each domain, finds its latest
    snapshot's risk score and tallies the risk_level. Uses Python-side
    deduplication to avoid DISTINCT ON (PostgreSQL-only).
    """
    # Join snapshots + risk scores, ordered so latest snapshot comes first
    rows = session.execute(
        select(DomainModel.id, RiskScoreModel.risk_level)
        .join(SnapshotModel, SnapshotModel.domain_id == DomainModel.id)
        .join(RiskScoreModel, RiskScoreModel.snapshot_id == SnapshotModel.id)
        .order_by(DomainModel.id, SnapshotModel.timestamp.desc())
    ).all()

    # Deduplicate: keep only the first (latest) risk_level per domain
    seen: set[str] = set()
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for domain_id, risk_level in rows:
        if domain_id in seen:
            continue
        seen.add(domain_id)
        if risk_level in counts:
            counts[risk_level] += 1

    return ThreatStatsResponse(
        total=sum(counts.values()),
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
    )