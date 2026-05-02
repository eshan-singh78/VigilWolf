"""Verify SSE connection limiting uses an asyncio.Semaphore for atomicity."""

import asyncio
import importlib
import sys
from pathlib import Path

# Ensure the backend root is on sys.path so ``routes.v2.events`` resolves
# regardless of where pytest is invoked from.
_BACKEND_ROOT = str(Path(__file__).resolve().parent.parent)
if _BACKEND_ROOT not in sys.path:
    sys.path.insert(0, _BACKEND_ROOT)


def test_sse_uses_semaphore():
    """The events module must expose _connection_semaphore as an asyncio.Semaphore."""
    from routes.v2 import events as events_module

    assert hasattr(events_module, "_connection_semaphore"), (
        "events module missing _connection_semaphore attribute"
    )
    assert isinstance(events_module._connection_semaphore, asyncio.Semaphore), (
        f"_connection_semaphore is {type(events_module._connection_semaphore).__name__}, "
        "expected asyncio.Semaphore"
    )
    assert events_module._connection_semaphore._value == events_module.MAX_SSE_CONNECTIONS, (
        "Semaphore initial value must equal MAX_SSE_CONNECTIONS"
    )