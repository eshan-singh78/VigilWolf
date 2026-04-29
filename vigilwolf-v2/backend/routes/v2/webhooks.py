"""VigilWolf v2 — Webhook API endpoints."""

from __future__ import annotations

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from database import WebhookModel, get_db
from services.alert_service import build_webhook_payload, sign_payload

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class WebhookCreate(BaseModel):
    name: str
    url: str
    secret: Optional[str] = None
    events: list[str] = Field(default_factory=lambda: ["phishing_detected"])
    enabled: bool = True
    filters: dict = Field(default_factory=dict)


class WebhookUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    secret: Optional[str] = None
    events: Optional[list[str]] = None
    enabled: Optional[bool] = None
    filters: Optional[dict] = None


class WebhookResponse(BaseModel):
    id: str
    name: str
    url: str
    secret: Optional[str] = None
    events: list
    enabled: bool
    filters: dict
    created_at: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class WebhookTestResponse(BaseModel):
    success: bool
    status_code: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _webhook_to_response(wh: WebhookModel) -> WebhookResponse:
    return WebhookResponse(
        id=wh.id,
        name=wh.name,
        url=wh.url,
        secret=wh.secret,
        events=wh.events if isinstance(wh.events, list) else [],
        enabled=wh.enabled,
        filters=wh.filters if isinstance(wh.filters, dict) else {},
        created_at=wh.created_at.isoformat() if wh.created_at else None,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/webhooks", status_code=201, )
def create_webhook(body: WebhookCreate, session: Session = Depends(get_db)) -> WebhookResponse:
    """Create a new webhook."""
    wh = WebhookModel(
        name=body.name,
        url=body.url,
        secret=body.secret,
        events=body.events,
        enabled=body.enabled,
        filters=body.filters,
    )
    session.add(wh)
    session.commit()
    session.refresh(wh)
    return _webhook_to_response(wh)


@router.get("/webhooks", )
def list_webhooks(session: Session = Depends(get_db)) -> list[WebhookResponse]:
    """List all webhooks."""
    rows = session.execute(select(WebhookModel)).scalars().all()
    return [_webhook_to_response(wh) for wh in rows]


@router.get("/webhooks/{webhook_id}", )
def get_webhook(webhook_id: str, session: Session = Depends(get_db)) -> WebhookResponse:
    """Get a single webhook by ID."""
    wh = session.get(WebhookModel, webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return _webhook_to_response(wh)


@router.put("/webhooks/{webhook_id}", )
def update_webhook(webhook_id: str, body: WebhookUpdate, session: Session = Depends(get_db)) -> WebhookResponse:
    """Update a webhook."""
    wh = session.get(WebhookModel, webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(wh, key, value)

    session.commit()
    session.refresh(wh)
    return _webhook_to_response(wh)


@router.delete("/webhooks/{webhook_id}", )
def delete_webhook(webhook_id: str, session: Session = Depends(get_db)) -> dict:
    """Delete a webhook."""
    wh = session.get(WebhookModel, webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    session.delete(wh)
    session.commit()
    return {"deleted": True, "id": webhook_id}


@router.post("/webhooks/{webhook_id}/test", )
def test_webhook(webhook_id: str, session: Session = Depends(get_db)) -> WebhookTestResponse:
    """Send a test payload to the webhook URL."""
    import requests as http_requests

    wh = session.get(WebhookModel, webhook_id)
    if not wh:
        raise HTTPException(status_code=404, detail="Webhook not found")

    payload = build_webhook_payload(
        event="test",
        domain="example.test.vigilwolf",
        score=0,
        risk_level="low",
        severity="low",
        dominant_signals=[],
        snapshot_id="test-snapshot-id",
        reasons=["Webhook test event"],
    )

    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if wh.secret:
        headers["X-VigilWolf-Signature"] = sign_payload(body_bytes, wh.secret)

    try:
        resp = http_requests.post(wh.url, data=body_bytes, headers=headers, timeout=10)
        return WebhookTestResponse(
            success=200 <= resp.status_code < 300,
            status_code=resp.status_code,
        )
    except http_requests.RequestException as exc:
        return WebhookTestResponse(
            success=False,
            error=str(exc),
        )