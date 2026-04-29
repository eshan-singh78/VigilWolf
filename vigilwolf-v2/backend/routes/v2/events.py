"""VigilWolf v2 — Server-Sent Events (SSE) endpoint for real-time updates.

Provides a single ``GET /api/v2/events`` endpoint that streams events to
connected clients. The endpoint is intentionally placed **outside** the
API-key-authenticated router so that SSE clients can connect without
passing a header-based API key (SSE browsers don't support custom headers
natively; authentication is expected to come from query-param tokens or
a separate mechanism in the future).

Event types:
  - ``threat_detected`` — a domain received a high/medium risk score
  - ``alert_dispatched``  — a webhook alert was dispatched
  - ``processing_update`` — a domain's processing state changed

Heartbeat comments (``: heartbeat``) are sent every 15 seconds when no
real events arrive, keeping the connection alive through proxies.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timezone

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from services.event_bus import event_bus

logger = logging.getLogger(__name__)

router = APIRouter()

# Seconds between heartbeat keep-alive comments when no real events arrive
HEARTBEAT_INTERVAL = 15


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------

async def _event_generator(request: Request) -> AsyncIterator[str]:
    """Yield SSE-formatted messages from the event bus.

    Subscribes to the global :pydata:`event_bus`, yields real events as
    they arrive, and falls back to heartbeat comments when the queue is
    idle for more than ``HEARTBEAT_INTERVAL`` seconds.
    """
    queue = event_bus.subscribe()
    try:
        while True:
            # Allow the client to disconnect cleanly
            if await request.is_disconnected():
                logger.info("SSE client disconnected")
                break

            try:
                event_type, data = await asyncio.wait_for(
                    queue.get(), timeout=HEARTBEAT_INTERVAL
                )
            except asyncio.TimeoutError:
                # No event arrived — send heartbeat to keep connection alive
                yield ": heartbeat\n\n"
                continue

            payload = {
                "event": event_type,
                "data": data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            yield f"data: {json.dumps(payload)}\n\n"

    except asyncio.CancelledError:
        logger.info("SSE generator cancelled (client disconnected)")
    finally:
        event_bus.unsubscribe(queue)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.get("/events")
async def sse_events(request: Request) -> StreamingResponse:
    """SSE stream for real-time threat and processing updates.

    This endpoint does **not** require an API-key header. SSE connections
    from browsers cannot set custom HTTP headers on the ``EventSource``
    object, so auth must be handled via query parameters or cookies if
    needed in the future.
    """
    return StreamingResponse(
        _event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )