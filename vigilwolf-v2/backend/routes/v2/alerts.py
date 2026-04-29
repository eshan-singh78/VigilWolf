"""VigilWolf v2 — Alert API endpoints."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from database import AlertModel, get_db

router = APIRouter()


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class AlertResponse(BaseModel):
    id: int
    event_type: str
    dedup_key: str
    domain_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    risk_level: Optional[str] = None
    severity: str
    score: Optional[int] = None
    webhook_id: Optional[str] = None
    status: str
    attempts: int
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AlertsListResponse(BaseModel):
    items: list[AlertResponse]
    next_cursor: Optional[str] = None
    total: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_to_response(alert: AlertModel) -> AlertResponse:
    return AlertResponse(
        id=alert.id,
        event_type=alert.event_type,
        dedup_key=alert.dedup_key,
        domain_id=alert.domain_id,
        snapshot_id=alert.snapshot_id,
        risk_level=alert.risk_level,
        severity=alert.severity,
        score=alert.score,
        webhook_id=alert.webhook_id,
        status=alert.status,
        attempts=alert.attempts,
        created_at=alert.created_at.isoformat() if alert.created_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/alerts", )
def list_alerts(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    session: Session = Depends(get_db),
) -> AlertsListResponse:
    """List alerts with cursor-based pagination and filters."""
    query = select(AlertModel)

    if severity:
        query = query.where(AlertModel.severity == severity)
    if status:
        query = query.where(AlertModel.status == status)
    if risk_level:
        query = query.where(AlertModel.risk_level == risk_level)

    # Total count
    count_query = select(func.count()).select_from(query.subquery())
    total = session.execute(count_query).scalar() or 0

    # Cursor pagination (cursor = last alert id as string)
    if cursor:
        try:
            cursor_id = int(cursor)
            query = query.where(AlertModel.id > cursor_id)
        except ValueError:
            pass

    query = query.order_by(AlertModel.id).limit(limit + 1)
    results = session.execute(query).scalars().all()

    items = [_alert_to_response(a) for a in results[:limit]]

    next_cursor = None
    if len(results) > limit:
        next_cursor = str(results[limit - 1].id)

    return AlertsListResponse(items=items, next_cursor=next_cursor, total=total)


@router.get("/alerts/{alert_id}", )
def get_alert(alert_id: int, session: Session = Depends(get_db)) -> AlertResponse:
    """Get alert detail."""
    alert = session.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alert_to_response(alert)


@router.post("/alerts/{alert_id}/retry", )
def retry_alert(alert_id: int, session: Session = Depends(get_db)) -> AlertResponse:
    """Retry a failed alert delivery."""
    alert = session.get(AlertModel, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if alert.status not in ("failed", "retrying"):
        raise HTTPException(status_code=400, detail="Alert is not in a retryable state")

    # Reset status for retry
    alert.status = "retrying"
    alert.attempts = 0
    session.commit()
    session.refresh(alert)

    return _alert_to_response(alert)