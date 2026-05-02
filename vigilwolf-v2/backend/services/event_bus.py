"""VigilWolf v2 event bus with Redis pub/sub + in-memory fallback."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

import config

logger = logging.getLogger(__name__)


class EventBus:
    """Redis-backed event bus with local in-memory fallback."""

    CHANNEL = "vigilwolf.events"

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[tuple[str, dict[str, Any]]]] = []
        self._lock = threading.Lock()
        self._redis = None
        self._redis_enabled = False
        self._init_redis()

    def _init_redis(self) -> None:
        if not config.REDIS_URL:
            return
        try:
            import redis

            self._redis = redis.Redis.from_url(
                config.REDIS_URL,
                db=config.REDIS_CACHE_DB,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=True,
            )
            self._redis.ping()
            self._redis_enabled = True
            logger.info("Event bus connected to Redis pub/sub")
        except Exception as exc:
            self._redis = None
            self._redis_enabled = False
            logger.warning("Event bus Redis unavailable, using in-memory fallback: %s", exc)

    # ------------------------------------------------------------------
    def publish(self, event_type: str, data: dict[str, Any]) -> None:
        """Broadcast event to Redis channel and local subscribers."""
        payload: tuple[str, dict[str, Any]] = (event_type, data)
        if self._redis_enabled and self._redis is not None:
            try:
                self._redis.publish(
                    self.CHANNEL,
                    json.dumps({"event_type": event_type, "data": data}),
                )
            except Exception:
                logger.exception("Failed to publish event to Redis")

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

    def subscribe(self) -> asyncio.Queue[tuple[str, dict[str, Any]]]:
        """Create a local fallback subscriber queue."""
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        with self._lock:
            self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[tuple[str, dict[str, Any]]]) -> None:
        """Remove a local fallback subscriber queue."""
        with self._lock:
            try:
                self._subscribers.remove(queue)
            except ValueError:
                pass  # already removed — idempotent

    async def iter_events(
        self,
        local_queue: asyncio.Queue[tuple[str, dict[str, Any]]],
    ):
        """Yield event tuples from Redis (preferred) or local queue fallback.

        When Redis is enabled, uses ``redis.asyncio`` so the event loop is
        never blocked by a synchronous ``get_message`` call.  The local queue
        is also drained on every iteration so that events published in-process
        (which Redis pub/sub does not reflect back to the same subscriber) are
        still delivered.
        """
        if self._redis_enabled and self._redis is not None:
            import redis.asyncio as aioredis

            async_redis = aioredis.Redis.from_url(
                config.REDIS_URL,
                db=config.REDIS_CACHE_DB,
                decode_responses=True,
            )
            pubsub = async_redis.pubsub()
            await pubsub.subscribe(self.CHANNEL)
            try:
                while True:
                    # Drain any events published in-process first — Redis
                    # pub/sub does not loop back to the same subscriber.
                    while not local_queue.empty():
                        try:
                            event_type, data = local_queue.get_nowait()
                            yield event_type, data
                        except asyncio.QueueEmpty:
                            break

                    msg = await pubsub.get_message(
                        ignore_subscribe_messages=True,
                        timeout=1.0,
                    )
                    if not msg:
                        continue
                    raw = msg.get("data")
                    if not raw:
                        continue
                    try:
                        parsed = json.loads(raw)
                        event_type = parsed.get("event_type")
                        data = parsed.get("data")
                        if isinstance(event_type, str) and isinstance(data, dict):
                            yield event_type, data
                    except Exception:
                        logger.exception("Failed to parse Redis event payload")
            finally:
                await pubsub.unsubscribe(self.CHANNEL)
                await pubsub.close()
                await async_redis.aclose()
            return

        while True:
            event_type, data = await local_queue.get()
            yield event_type, data

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


event_bus = EventBus()