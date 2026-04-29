"""Starlette middleware that wraps /api/v2/* JSON responses in a standard envelope.

Envelope format for single-item responses::

    {
        "data": <original response body>,
        "meta": {
            "request_id": "abc123",
            "timestamp": "2026-04-28T12:00:00Z"
        }
    }

For list responses with pagination fields (``next_cursor``, ``has_more``,
``total``), those keys are promoted to ``meta`` and the ``items`` value
becomes ``data``::

    {
        "data": [<items>],
        "meta": {
            "request_id": "...",
            "timestamp": "...",
            "next_cursor": "...",
            "has_more": true,
            "total": 42
        }
    }

Behaviour:
- Only wraps paths starting with ``/api/v2/``.
- Error responses (4xx, 5xx) are passed through unchanged.
- Non-JSON responses are passed through unchanged.
- ``/health`` and ``/metrics`` are not v2 paths and are therefore left alone.
"""

import json
import uuid
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

PAGINATION_KEYS = frozenset({"next_cursor", "has_more", "total"})


class EnvelopeMiddleware(BaseHTTPMiddleware):
    """Wrap successful /api/v2/* JSON responses in a standard envelope."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        # Attach a short request-id to state early so downstream code can use it
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id

        response = await call_next(request)

        # ── Skip non-v2 paths ───────────────────────────────────────────
        if not request.url.path.startswith("/api/v2/"):
            return response

        # ── Skip error responses ────────────────────────────────────────
        if response.status_code >= 400:
            return response

        # ── Skip non-JSON responses ─────────────────────────────────────
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return response

        # ── Read response body ───────────────────────────────────────────
        body_chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            if isinstance(chunk, str):
                body_chunks.append(chunk.encode())
            else:
                body_chunks.append(chunk)
        body = b"".join(body_chunks)

        if not body:
            return Response(content=body, status_code=response.status_code,
                            media_type=content_type)

        # ── Parse JSON ──────────────────────────────────────────────────
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return Response(content=body, status_code=response.status_code,
                            media_type=content_type)

        # ── Build envelope ───────────────────────────────────────────────
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        meta: dict = {
            "request_id": request_id,
            "timestamp": timestamp,
        }

        if isinstance(data, dict):
            # Promote pagination keys into meta
            for key in PAGINATION_KEYS:
                if key in data:
                    meta[key] = data.pop(key)

            # If the body has an "items" key, data becomes the items value
            if "items" in data:
                envelope_data = data.pop("items")
            else:
                envelope_data = data
        else:
            # Primitive or list body — wrap as-is
            envelope_data = data

        envelope = {
            "data": envelope_data,
            "meta": meta,
        }

        return JSONResponse(content=envelope, status_code=response.status_code)