"""Rate limiting with Redis support (falls back to in-memory).

Supports:
- Per-IP rate limiting with sliding window
- Per-endpoint rate limiting rules
- Redis for distributed deployments
- In-memory fallback for single-node deployments
"""
import time
import logging
import threading
import uuid
from typing import Dict, Optional
from dataclasses import dataclass

import config

logger = logging.getLogger(__name__)


@dataclass
class RateLimitRule:
    """Rate limit rule for an endpoint."""
    requests: int
    window_seconds: int


# Default rules per endpoint
DEFAULT_RULES: Dict[str, RateLimitRule] = {
    "default": RateLimitRule(requests=60, window_seconds=60),
    "/whois": RateLimitRule(requests=30, window_seconds=60),
    "/nrd-latest": RateLimitRule(requests=10, window_seconds=60),
    "/brand-search": RateLimitRule(requests=20, window_seconds=60),
    "/dump-nrd": RateLimitRule(requests=5, window_seconds=300),
    "/monitoring/groups": RateLimitRule(requests=30, window_seconds=60),
}


class InMemoryRateLimiter:
    """Thread-safe in-memory rate limiter with TTL-based eviction."""

    def __init__(self, max_keys: int = 10_000):
        self._store: Dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def _prune_expired(self, now: float) -> None:
        """Remove keys with all timestamps older than the longest window."""
        max_window = max((r.window_seconds for r in DEFAULT_RULES.values()), default=300)
        cutoff = now - max_window
        expired = [k for k, v in self._store.items() if not v or v[-1] < cutoff]
        for k in expired:
            del self._store[k]

    def _evict_oldest_if_needed(self) -> None:
        """Evict oldest keys if store exceeds max size."""
        if len(self._store) <= self._max_keys:
            return
        # Sort by most recent timestamp, evict oldest
        sorted_keys = sorted(
            self._store.items(),
            key=lambda item: max(item[1]) if item[1] else 0
        )
        to_evict = len(self._store) - self._max_keys
        for i in range(to_evict):
            del self._store[sorted_keys[i][0]]

    def is_allowed(self, key: str, rule: RateLimitRule) -> bool:
        now = time.time()
        window_start = now - rule.window_seconds

        with self._lock:
            # Periodic cleanup of expired keys
            if len(self._store) > self._max_keys // 2:
                self._prune_expired(now)
                self._evict_oldest_if_needed()

            # Get existing requests for this key
            requests = self._store.get(key, [])

            # Filter to current window
            requests = [t for t in requests if t > window_start]

            if len(requests) >= rule.requests:
                self._store[key] = requests
                return False

            requests.append(now)
            self._store[key] = requests
            return True

    def get_remaining(self, key: str, rule: RateLimitRule) -> int:
        now = time.time()
        window_start = now - rule.window_seconds

        with self._lock:
            requests = self._store.get(key, [])
            requests = [t for t in requests if t > window_start]
            return max(0, rule.requests - len(requests))


class RedisRateLimiter:
    """Redis-backed rate limiter for distributed deployments."""

    def __init__(self, redis_url: str):
        try:
            import redis as redis_lib
            self._redis = redis_lib.from_url(redis_url, decode_responses=True)
            self._available = True
        except Exception as e:
            logger.warning(f"Redis not available, falling back to in-memory: {e}")
            self._available = False
            self._fallback = InMemoryRateLimiter()

    def is_allowed(self, key: str, rule: RateLimitRule) -> bool:
        if not self._available:
            return self._fallback.is_allowed(key, rule)

        try:
            now = time.time()
            window_start = now - rule.window_seconds
            redis_key = f"rate_limit:{key}"

            # Use Redis sorted set for sliding window
            pipe = self._redis.pipeline()
            pipe.zremrangebyscore(redis_key, 0, window_start)
            pipe.zcard(redis_key)
            pipe.zadd(redis_key, {f"{now}:{uuid.uuid4()}": now})
            pipe.expire(redis_key, rule.window_seconds + 1)
            _, current_count, _, _ = pipe.execute()

            return current_count < rule.requests
        except Exception as e:
            logger.warning(f"Redis rate limit error: {e}, falling back to in-memory")
            return self._fallback.is_allowed(key, rule)

    def get_remaining(self, key: str, rule: RateLimitRule) -> int:
        if not self._available:
            return self._fallback.get_remaining(key, rule)

        try:
            now = time.time()
            window_start = now - rule.window_seconds
            redis_key = f"rate_limit:{key}"
            self._redis.zremrangebyscore(redis_key, 0, window_start)
            current_count = self._redis.zcard(redis_key)
            return max(0, rule.requests - current_count)
        except Exception:
            return self._fallback.get_remaining(key, rule)


# Global rate limiter instance
_rate_limiter: Optional[InMemoryRateLimiter | RedisRateLimiter] = None


def get_rate_limiter():
    """Get the global rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        if config.REDIS_URL:
            _rate_limiter = RedisRateLimiter(config.REDIS_URL)
        else:
            _rate_limiter = InMemoryRateLimiter()
    return _rate_limiter


def check_rate_limit(client_ip: str, endpoint: str) -> tuple[bool, int]:
    """Check if a request is within rate limits.

    Returns:
        (allowed, remaining_requests)
    """
    if config.RATE_LIMIT_PER_MINUTE <= 0:
        return True, -1

    limiter = get_rate_limiter()
    rule = DEFAULT_RULES.get(endpoint, DEFAULT_RULES["default"])
    key = f"{client_ip}:{endpoint}"
    allowed = limiter.is_allowed(key, rule)
    remaining = limiter.get_remaining(key, rule)
    return allowed, remaining
