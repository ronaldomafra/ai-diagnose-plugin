"""Deduplicated queue for actions awaiting local approval."""

from __future__ import annotations

import asyncio
from collections import deque
from contextlib import suppress


class ActionQueue:
    """Queue request identifiers once until a consumer acknowledges them."""

    def __init__(self) -> None:
        self._condition = asyncio.Condition()
        self._pending: deque[str] = deque()
        self._in_flight: set[str] = set()
        self._queued: set[str] = set()

    async def put(self, request_id: str) -> bool:
        """Add an identifier, returning false when it was already queued."""
        async with self._condition:
            if request_id in self._queued:
                return False
            self._queued.add(request_id)
            self._pending.append(request_id)
            self._condition.notify()
            return True

    async def get(self) -> str:
        """Wait for the next pending identifier."""
        async with self._condition:
            await self._condition.wait_for(lambda: bool(self._pending))
            request_id = self._pending.popleft()
            self._in_flight.add(request_id)
            return request_id

    async def acknowledge(self, request_id: str) -> None:
        """Allow a request to be queued again after its current item is handled."""
        async with self._condition:
            with suppress(ValueError):
                self._pending.remove(request_id)
            self._in_flight.discard(request_id)
            self._queued.discard(request_id)

    def empty(self) -> bool:
        return not self._pending
