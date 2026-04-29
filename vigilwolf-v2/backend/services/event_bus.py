"""VigilWolf v2 — In-memory pub/sub event bus for real-time SSE streaming.

Thread-safe and async-safe: ``publish`` may be called from synchronous
worker code (the pipeline) while ``subscribe`` / ``unsubscribe`` are used
from async SSE handlers.

Usage::

    from services.event_bus import event_bus

    # Publisher (worker / pipeline):
    event_bus.publish("threat_detected", {"domain": "evil.com", "score": 85})

    # Subscriber (SSE endpoint):
    queue = event_bus.subscribe()
    try:
        event_type, data = await asyncio.wait_for(queue.get(), timeout=15)
    except asyncio.TimeoutError:
        # heartbeat
    finally:
        event_bus.unsubscribe(queue)
"""
from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

logger = logging.getLogger(__name__)


class EventBus:
    """Simple in-memory publish/subscribe event bus.

    Subscribers receive ``(event_type, data)`` tuples via ``asyncio.Queue``
    instances. The bus is designed for same-process use — it does **not**
    persist across restarts or scale to multiple processes (use Redis
    pub/sub for that).
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[tuple[str, dict[str, Any]]]] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast an event to every subscribed queue.

        Safe to call from any thread — queues that belong to a running
        event loop are fed via ``call_soon_threadsafe`` so the put is
        scheduled on the correct loop.
        """
        payload: tuple[str, dict[str, Any]] = (event_type, data)
        with self._lock:
            subscribers = list(self._subscribers)

        for queue in subscribers:
            try:
                # If the queue belongs to an event loop running in another
                # thread, schedule the put on that loop.
                loop = self._get_loop(queue)
                if loop is not None and loop.is_running():
                    loop.call_soon_threadsafe(self._safe_put, queue, payload)
                else:
                    # Fallback: synchronous put (works when caller is on
                    # the same thread as the event loop or loop isn't running)
                    self._safe_put(queue, payload)
            except Exception:
                logger.exception("Failed to publish event to subscriber queue")

    # ------------------------------------------------------------------
    # Subscribe / Unsubscribe
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue[tuple[str, dict[str, Any]]]:
        """Create a new subscriber queue and register it.

        Callers should keep a reference to the returned queue and pass it
        to :meth:`unsubscribe` when they disconnect.
        """
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        with self._lock:
            self._subscribers.append(queue)
        logger.info("SSE subscriber added (total: %d)", len(self._subscribers))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[tuple[str, dict[str, Any]]]) -> None:
        """Remove a previously registered subscriber queue."""
        with self._lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass  # already removed — idempotent
        logger.info("SSE subscriber removed (total: %d)", len(self._subscribers))

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_put(
        queue: asyncio.Queue[tuple[str, dict[str, Any]]],
        payload: tuple[str, dict[str, Any]],
    ) -> None:
        """Put *payload* on *queue*, dropping if full to avoid blocking."""
        try:
            queue.put_nowait(payload)
        except asyncio.QueueFull:
            logger.warning("Event bus queue full — dropping event %s", payload[0])

    @staticmethod
    def _get_loop(queue: asyncio.Queue) -> asyncio.AbstractEventLoop | None:
        """Best-effort retrieval of the event loop bound to *queue*."""
        try:
            # asyncio.Queue stores the loop lazily; introspect it.
            return queue._loop  # type: ignore[attr-defined]
        except AttributeError:
            return None


# ---------------------------------------------------------------------------
# Module-level singleton — import this from other modules
# ---------------------------------------------------------------------------
event_bus = EventBus()