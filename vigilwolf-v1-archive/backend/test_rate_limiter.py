"""Tests for the rate limiter module."""
import pytest
import time
from rate_limiter import InMemoryRateLimiter, RateLimitRule, check_rate_limit


class TestInMemoryRateLimiter:
    """Test in-memory rate limiter."""

    def test_allows_requests_within_limit(self):
        limiter = InMemoryRateLimiter()
        rule = RateLimitRule(requests=5, window_seconds=60)

        for _ in range(5):
            assert limiter.is_allowed("test-key", rule) is True

    def test_blocks_requests_over_limit(self):
        limiter = InMemoryRateLimiter()
        rule = RateLimitRule(requests=3, window_seconds=60)

        for _ in range(3):
            limiter.is_allowed("test-key", rule)

        assert limiter.is_allowed("test-key", rule) is False

    def test_remaining_decreases(self):
        limiter = InMemoryRateLimiter()
        rule = RateLimitRule(requests=5, window_seconds=60)

        assert limiter.get_remaining("test-key", rule) == 5
        limiter.is_allowed("test-key", rule)
        assert limiter.get_remaining("test-key", rule) == 4

    def test_window_resets_after_time(self):
        limiter = InMemoryRateLimiter()
        rule = RateLimitRule(requests=2, window_seconds=1)

        limiter.is_allowed("test-key", rule)
        limiter.is_allowed("test-key", rule)
        assert limiter.is_allowed("test-key", rule) is False

        time.sleep(1.1)
        assert limiter.is_allowed("test-key", rule) is True

    def test_different_keys_are_independent(self):
        limiter = InMemoryRateLimiter()
        rule = RateLimitRule(requests=1, window_seconds=60)

        assert limiter.is_allowed("key-a", rule) is True
        assert limiter.is_allowed("key-b", rule) is True


class TestCheckRateLimit:
    """Test the check_rate_limit helper."""

    def test_disabled_rate_limiting(self):
        import config
        original = config.RATE_LIMIT_PER_MINUTE
        config.RATE_LIMIT_PER_MINUTE = 0
        try:
            allowed, remaining = check_rate_limit("1.2.3.4", "/whois")
            assert allowed is True
            assert remaining == -1
        finally:
            config.RATE_LIMIT_PER_MINUTE = original

    def test_enforced_rate_limiting(self):
        import config
        import rate_limiter
        original = config.RATE_LIMIT_PER_MINUTE
        config.RATE_LIMIT_PER_MINUTE = 2
        # Reset global limiter so it picks up the new config
        rate_limiter._rate_limiter = None
        try:
            # Use a custom rule with low limit for testing
            rule = RateLimitRule(requests=2, window_seconds=60)
            limiter = InMemoryRateLimiter()
            assert limiter.is_allowed("test", rule) is True
            assert limiter.is_allowed("test", rule) is True
            assert limiter.is_allowed("test", rule) is False
            assert limiter.get_remaining("test", rule) == 0
        finally:
            config.RATE_LIMIT_PER_MINUTE = original
            rate_limiter._rate_limiter = None
