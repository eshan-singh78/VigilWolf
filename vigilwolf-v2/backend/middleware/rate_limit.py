"""Sliding-window rate limiter middleware with Redis or in-memory fallback."""
import logging
import time
from collections import defaultdict
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config import RATE_LIMIT_PER_MINUTE, REDIS_URL, REDIS_RATE_LIMIT_DB

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP rate limiting using a sliding window.

    Attempts to use Redis for rate limiting when available so that limits
    are shared across workers. Falls back to an in-memory store when Redis
    is unreachable.
    """

    _redis_client = None
    _redis_warned = False

    @classmethod
    def _init_redis(cls) -> None:
        """Attempt to connect to Redis. Sets _redis_client on success."""
        if cls._redis_client is not None or not REDIS_URL:
            return
        try:
            import redis
            client = redis.Redis.from_url(
                REDIS_URL, db=REDIS_RATE_LIMIT_DB, socket_timeout=2, socket_connect_timeout=2
            )
            client.ping()
            cls._redis_client = client
            logger.info("Rate limiter connected to Redis at %s (db=%s)", REDIS_URL, REDIS_RATE_LIMIT_DB)
        except Exception as exc:
            cls._redis_client = None
            if not cls._redis_warned:
                logger.warning(
                    "Redis unavailable for rate limiting (%s); falling back to in-memory mode",
                    exc,
                )
                cls._redis_warned = True

    def __init__(self, app, requests_per_minute: int = RATE_LIMIT_PER_MINUTE,
                 exempt_paths: Optional[list[str]] = None):
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.exempt_paths = set(exempt_paths or ["/health", "/metrics"])
        self._requests: dict[str, list[float]] = defaultdict(list)
        # Try Redis connection on first instantiation
        self._init_redis()

    async def dispatch(self, request: Request, call_next):
        if request.url.path in self.exempt_paths:
            return await call_next(request)

        client_ip = self._get_client_ip(request)

        if self._redis_client is not None:
            return await self._redis_dispatch(request, call_next, client_ip)
        return await self._in_memory_dispatch(request, call_next, client_ip)

    # -- Redis-backed path ---------------------------------------------------

    async def _redis_dispatch(self, request: Request, call_next, client_ip: str):
        now = time.time()
        window_start = now - 60.0
        key = f"rate_limit:{client_ip}"

        try:
            pipe = self._redis_client.pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {f"{now}": now})
            pipe.zcard(key)
            pipe.expire(key, 120)
            _, _, count, _ = pipe.execute()
            if count > self.requests_per_minute:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                )
        except Exception as exc:
            # Redis became unreachable mid-flight — fall back once per process
            if not self.__class__._redis_warned:
                logger.warning(
                    "Redis rate-limit call failed (%s); falling back to in-memory mode",
                    exc,
                )
                self.__class__._redis_warned = True
            self._redis_client = None
            return await self._in_memory_dispatch(request, call_next, client_ip)

        return await call_next(request)

    # -- In-memory fallback path (original implementation) -------------------

    async def _in_memory_dispatch(self, request: Request, call_next, client_ip: str):
        now = time.time()
        window = 60.0

        # Prune old entries
        timestamps = self._requests[client_ip]
        pruned = [t for t in timestamps if now - t < window]
        if pruned:
            self._requests[client_ip] = pruned
        elif client_ip in self._requests:
            del self._requests[client_ip]
            pruned = []

        if len(pruned) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )

        self._requests[client_ip].append(now)
        return await call_next(request)

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Resolve client IP, only trusting proxy headers from configured proxies."""
        from config import TRUSTED_PROXIES
        direct_ip = request.client.host if request.client else "unknown"
        if TRUSTED_PROXIES and direct_ip in TRUSTED_PROXIES:
            xff = request.headers.get("x-forwarded-for", "")
            if xff:
                first = xff.split(",")[0].strip()
                if first:
                    return first
            xrip = request.headers.get("x-real-ip", "").strip()
            if xrip:
                return xrip
        return direct_ip