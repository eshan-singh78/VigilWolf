"""Tests for async event bus — local-queue paths.

These tests exercise the in-memory fallback path of ``EventBus.iter_events()``
and the ``publish`` / ``subscribe`` round-trip, neither of which requires a
running Redis instance.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

# Ensure the backend package is importable regardless of cwd.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Force Redis off so EventBus always uses the in-memory fallback.
os.environ["REDIS_URL"] = ""

import importlib

import config
importlib.reload(config)

from services.event_bus import EventBus  # noqa: E402  (after config reload)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def bus() -> EventBus:
    """Return a fresh EventBus instance with Redis disabled."""
    return EventBus()


@pytest.fixture()
def local_queue(bus: EventBus) -> asyncio.Queue:
    """Return a subscriber queue registered on *bus*."""
    return bus.subscribe()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_iter_events_yields_from_local_queue(
    bus: EventBus,
    local_queue: asyncio.Queue,
) -> None:
    """When Redis is unavailable, iter_events yields from the local queue."""
    expected_events: list[tuple[str, dict]] = [
        ("domain.created", {"domain": "example.com"}),
        ("alert.fired", {"level": "high", "domain": "evil.com"}),
    ]

    # Publish into the local subscriber queue.
    for event_type, data in expected_events:
        bus.publish(event_type, data)

    # Consume exactly the number of events we published.
    collected: list[tuple[str, dict]] = []
    async for event_type, data in bus.iter_events(local_queue):
        collected.append((event_type, data))
        if len(collected) == len(expected_events):
            break

    assert collected == expected_events


@pytest.mark.asyncio
async def test_publish_and_subscribe_local(bus: EventBus) -> None:
    """Local publish/subscribe round-trip works end-to-end."""
    queue = bus.subscribe()

    bus.publish("test.event", {"key": "value"})
    bus.publish("test.another", {"num": 42})

    # The two events should be waiting on the queue.
    first = queue.get_nowait()
    second = queue.get_nowait()

    assert first == ("test.event", {"key": "value"})
    assert second == ("test.another", {"num": 42})

    # Cleanup — unsubscribe should remove the queue without error.
    bus.unsubscribe(queue)
    assert queue not in bus._subscribers