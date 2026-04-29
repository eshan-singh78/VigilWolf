"""Alert Service — Webhook delivery for VigilWolf v2.

Handles outbound webhook notifications when high-risk domains are detected.
Supports HMAC-SHA256 signing, dedup windows, retry with jitter, and fan-out
isolation per webhook.
"""
from __future__ import annotations

import hmac
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from hashlib import sha256
from typing import Optional

import requests

from config import ALERTS_DRY_RUN, ALERTS_ENABLED
from plugins.base import SnapshotContext

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEDUP_WINDOW_SECONDS = 600  # 10 minutes

# ---------------------------------------------------------------------------
# Pure helpers (testable without DB / HTTP)
# ---------------------------------------------------------------------------


def build_webhook_payload(
    event: str,
    domain: str,
    score: int,
    risk_level: str,
    severity: str,
    dominant_signals: list[str],
    snapshot_id: str,
    reasons: list[str],
    iocs: Optional[list[str]] = None,
    campaign_id: Optional[str] = None,
) -> dict:
    """Build the standardised webhook JSON payload.

    Args:
        event: Event type string (e.g. "phishing_detected").
        domain: The monitored domain that triggered the alert.
        score: Normalised risk score (0-100).
        risk_level: "low" | "medium" | "high".
        severity: "low" | "medium" | "high" | "critical".
        dominant_signals: Top contributing plugin names.
        snapshot_id: ID of the snapshot that triggered the alert.
        reasons: Human-readable reason strings.
        iocs: Optional list of indicators of compromise.
        campaign_id: Optional campaign correlation ID.

    Returns:
        Dict ready for JSON serialization.
    """
    event_id = "evt_" + uuid.uuid4().hex[:12]
    dedup_key = f"{event}:{snapshot_id}"
    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y-%m-%dT%H:%M:%S.") + now_utc.strftime("%f")[:3] + "Z"

    return {
        "id": event_id,
        "version": "1.0",
        "event": event,
        "dedup_key": dedup_key,
        "timestamp": timestamp,
        "data": {
            "domain": domain,
            "score": score,
            "risk_level": risk_level,
            "severity": severity,
            "dominant_signals": dominant_signals,
            "reasons": reasons,
            "iocs": iocs if iocs is not None else [],
            "snapshot_id": snapshot_id,
            "campaign": campaign_id,
            "screenshot_url": None,
        },
    }


def _matches_filters(payload: dict, filters: dict) -> bool:
    """Check whether a webhook payload matches the given filter criteria.

    If *filters* is ``None``, empty, or ``{}``, the payload matches everything
    (no filters = pass-through).

    Supported filter keys:
      - ``min_score`` (int/float): payload score must be >= this value.
      - ``severity`` (list[str]): payload severity must be in this list.
      - ``domains`` (list[str]): payload domain must contain at least one
        substring from this list.
      - ``exclude_tags`` (list[str]): if any tag in the payload's
        dominant_signals or any reason string matches an excluded tag, the
        payload is rejected.

    Defensive: if a filter value is the wrong type it is silently skipped
    (treated as no filter).

    Args:
        payload: The webhook payload dict (must contain ``payload["data"]``).
        filters: Filter criteria dict (may be ``None`` or empty).

    Returns:
        True if the payload passes all filters, False otherwise.
    """
    if not filters:
        return True

    data = payload.get("data", {})

    # -- min_score -----------------------------------------------------------
    min_score = filters.get("min_score")
    if min_score is not None:
        if not isinstance(min_score, (int, float)):
            pass  # wrong type — treat as no filter
        else:
            try:
                if data.get("score", 0) < min_score:
                    return False
            except (TypeError, ValueError):
                pass  # score is not comparable — treat as no filter

    # -- severity ------------------------------------------------------------
    severity_filter = filters.get("severity")
    if severity_filter is not None:
        if not isinstance(severity_filter, list):
            pass  # wrong type — treat as no filter
        else:
            payload_severity = data.get("severity")
            if payload_severity not in severity_filter:
                return False

    # -- domains -------------------------------------------------------------
    domains_filter = filters.get("domains")
    if domains_filter is not None:
        if not isinstance(domains_filter, list):
            pass  # wrong type — treat as no filter
        else:
            payload_domain = data.get("domain", "")
            if not any(sub in payload_domain for sub in domains_filter):
                return False

    # -- exclude_tags ---------------------------------------------------------
    exclude_tags = filters.get("exclude_tags")
    if exclude_tags is not None:
        if not isinstance(exclude_tags, list):
            pass  # wrong type — treat as no filter
        else:
            # Gather all taggable strings from the payload.
            tags_to_check: list[str] = list(data.get("dominant_signals", []))
            for reason in data.get("reasons", []):
                if isinstance(reason, str):
                    tags_to_check.append(reason)
            for tag in exclude_tags:
                if not isinstance(tag, str):
                    continue
                if any(tag in t for t in tags_to_check if isinstance(t, str)):
                    return False

    return True


def sign_payload(body: bytes, secret: str) -> str:
    """Sign raw body bytes with HMAC-SHA256 using the given secret.

    Args:
        body: Raw JSON bytes to sign.
        secret: Webhook shared secret.

    Returns:
        Signature in the format ``sha256=<hex_digest>``.
    """
    digest = hmac.new(secret.encode(), body, sha256).hexdigest()
    return f"sha256={digest}"


# ---------------------------------------------------------------------------
# AlertService
# ---------------------------------------------------------------------------


class AlertService:
    """Webhook alert delivery service.

    Queries enabled webhooks from the database, checks event subscriptions and
    dedup windows, then delivers payloads with HMAC signing and retry with
    jitter.
    """

    def __init__(self) -> None:
        self._session = None

    # -- public entry point --------------------------------------------------

    def send_alert(
        self,
        ctx: SnapshotContext,
        score_outcome: dict,
        session: Optional[object] = None,
    ) -> None:
        """Dispatch alerts for a scored snapshot to all matching webhooks.

        Args:
            ctx: SnapshotContext from the analysis pipeline.
            score_outcome: Dict returned by ScoringService.calculate_score().
            session: Optional SQLAlchemy session. If None, one is created.
        """
        if not ALERTS_ENABLED:
            logger.debug("Alerts disabled; skipping send_alert for %s", ctx.domain)
            return

        # Lazy imports so this module loads without DB dependency.
        from database import AlertModel, WebhookModel  # type: ignore[import-untyped]

        if session is None:
            from database import get_session  # type: ignore[import-untyped]
            session = get_session()

        # Determine event type.
        hard_signal = score_outcome.get("hard_signal", False)
        event = "phishing_detected"  # default; hard signal uses the same event

        # Build the standardised payload.
        payload = build_webhook_payload(
            event=event,
            domain=ctx.domain,
            score=score_outcome.get("score", 0),
            risk_level=score_outcome.get("risk_level", "low"),
            severity=score_outcome.get("severity", "low"),
            dominant_signals=score_outcome.get("dominant_signals", []),
            snapshot_id=ctx.snapshot_id,
            reasons=score_outcome.get("reasons", []),
        )

        # Query enabled webhooks.
        webhooks = session.query(WebhookModel).filter(
            WebhookModel.enabled == True  # noqa: E712 — SQLAlchemy filter
        ).all()

        logger.info("Found %d enabled webhooks for event %s", len(webhooks), event)

        for webhook in webhooks:
            # Check event subscription.
            subscribed_events = webhook.events or []
            if event not in subscribed_events:
                logger.debug(
                    "Webhook %s not subscribed to %s; skipping.",
                    webhook.id, event,
                )
                continue

            # Check webhook filter matching.
            webhook_filters = webhook.filters if hasattr(webhook, 'filters') else {}
            if not _matches_filters(payload, webhook_filters):
                logger.debug("Webhook %s filters not matched; skipping.", webhook.id)
                continue

            # Check dedup window.
            dedup_key = payload["dedup_key"]
            cutoff = datetime.now(timezone.utc).timestamp() - DEDUP_WINDOW_SECONDS
            existing = session.query(AlertModel).filter(
                AlertModel.dedup_key == dedup_key,
                AlertModel.webhook_id == webhook.id,
            ).all()

            # Filter to alerts within the dedup window.
            is_dup = False
            for alert in existing:
                if alert.created_at is not None:
                    alert_ts = alert.created_at.replace(
                        tzinfo=timezone.utc
                    ).timestamp()
                    if alert_ts >= cutoff:
                        is_dup = True
                        break

            if is_dup:
                logger.debug(
                    "Dedup hit for dedup_key=%s webhook=%s; skipping.",
                    dedup_key, webhook.id,
                )
                continue

            # Deliver (fan-out per webhook, isolated).
            try:
                self._deliver_webhook(
                    webhook, payload, ctx, score_outcome, session,
                )
            except Exception:
                logger.exception(
                    "Error delivering webhook %s (non-fatal, continuing).",
                    webhook.id,
                )

    # -- internal delivery ---------------------------------------------------

    def _deliver_webhook(
        self,
        webhook,
        payload: dict,
        ctx: SnapshotContext,
        score_outcome: dict,
        session,
    ) -> None:
        """Deliver a single webhook payload with retry and jitter.

        Creates an AlertModel row, then attempts up to 3 deliveries with
        exponential backoff + jitter for server errors or connection issues.
        Client errors (4xx) are not retried.
        """
        from database import AlertModel  # type: ignore[import-untyped]

        body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if webhook.secret:
            headers["X-VigilWolf-Signature"] = sign_payload(body_bytes, webhook.secret)

        # Create alert record.
        alert = AlertModel(
            event_type=payload["event"],
            dedup_key=payload["dedup_key"],
            domain_id=ctx.snapshot_record.get("domain_id") if ctx.snapshot_record else None,
            snapshot_id=ctx.snapshot_id,
            risk_level=score_outcome.get("risk_level"),
            severity=score_outcome.get("severity", "low"),
            score=score_outcome.get("score", 0),
            webhook_id=webhook.id,
            payload=payload,
            payload_version="1.0",
            status="retrying",
            attempts=0,
        )
        session.add(alert)
        session.flush()  # get the alert.id for logging

        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            alert.attempts = attempt
            alert.last_attempt_at = datetime.now(timezone.utc)

            if ALERTS_DRY_RUN:
                logger.info(
                    "DRY RUN — would POST to %s (attempt %d/%d) payload=%s",
                    webhook.url, attempt, max_attempts, payload["id"],
                )
                alert.status = "sent"
                session.commit()
                return

            try:
                resp = requests.post(
                    webhook.url,
                    data=body_bytes,
                    headers=headers,
                    timeout=10,
                )
                if 200 <= resp.status_code < 300:
                    alert.status = "sent"
                    session.commit()
                    logger.info(
                        "Webhook %s delivered (HTTP %d) attempt %d/%d",
                        webhook.id, resp.status_code, attempt, max_attempts,
                    )
                    return
                elif 400 <= resp.status_code < 500:
                    # Client error — do not retry.
                    alert.status = "failed"
                    session.commit()
                    logger.warning(
                        "Webhook %s returned %d (client error, not retrying).",
                        webhook.id, resp.status_code,
                    )
                    return
                else:
                    # 5xx — retry with backoff.
                    logger.warning(
                        "Webhook %s returned HTTP %d (attempt %d); will retry.",
                        webhook.id, resp.status_code, attempt,
                    )
            except (requests.ConnectionError, requests.Timeout) as exc:
                logger.warning(
                    "Webhook %s connection error (attempt %d): %s",
                    webhook.id, attempt, exc,
                )
            except requests.RequestException as exc:
                logger.warning(
                    "Webhook %s request error (attempt %d): %s",
                    webhook.id, attempt, exc,
                )

            # Exponential backoff + jitter before next attempt.
            if attempt < max_attempts:
                delay = (2 ** attempt) + random.uniform(0, 1)
                logger.debug("Backing off %.2fs before retry %d", delay, attempt + 1)
                time.sleep(delay)

        # All attempts exhausted.
        alert.status = "failed"
        session.commit()
        logger.error(
            "Webhook %s delivery failed after %d attempts.", webhook.id, max_attempts,
        )