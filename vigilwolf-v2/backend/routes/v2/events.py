"""VigilWolf v2 — Server-Sent Events (SSE) endpoint for real-time updates.

Provides a single ``GET /api/v2/events`` endpoint that streams events to
connected clients. Authentication is enforced via the X-API-Key header
(the SSE endpoint is now mounted under the authenticated v2 router).

For browser EventSource connections that cannot set custom headers, clients
should use a proxy or token-based short-lived access mechanism. The insecure
query-param API key approach has been removed.

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

# Maximum concurrent SSE connections to prevent resource exhaustion
MAX_SSE_CONNECTIONS = 50

_connection_semaphore = asyncio.Semaphore(MAX_SSE_CONNECTIONS)


# ---------------------------------------------------------------------------
# SSE generator
# ---------------------------------------------------------------------------

async def _event_generator(request: Request) -> AsyncIterator[str]:
    """Yield SSE-formatted messages from the event bus.

    Subscribes to the global :pydata:`event_bus`, yields real events as
    they arrive, and falls back to heartbeat comments when the queue is
    idle for more than ``HEARTBEAT_INTERVAL`` seconds.

    Connection limiting is handled atomically via
    :pydata:`_connection_semaphore`.
    """
    async with _connection_semaphore:
        queue = event_bus.subscribe()
        stream = event_bus.iter_events(queue)
        try:
            while True:
                if await request.is_disconnected():
                    logger.info("SSE client disconnected")
                    break

                try:
                    event_type, data = await asyncio.wait_for(
                        anext(stream), timeout=HEARTBEAT_INTERVAL
                    )
                except asyncio.TimeoutError:
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

    Auth is enforced via the X-API-Key header (mounted under the authenticated
    v2 router). Connection limit enforced to prevent resource exhaustion.
    """
    if _connection_semaphore._value <= 0:
        from fastapi import HTTPException
        raise HTTPException(status_code=429, detail="Too many SSE connections")

    return StreamingResponse(
        _event_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )