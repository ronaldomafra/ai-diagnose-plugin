from __future__ import annotations

import pytest

from diagnose.terminal.action_queue import ActionQueue


@pytest.mark.asyncio
async def test_action_queue_deduplicates_until_acknowledged() -> None:
    queue = ActionQueue()

    assert await queue.put("REQ-1") is True
    assert await queue.put("REQ-1") is False
    assert await queue.get() == "REQ-1"

    await queue.acknowledge("REQ-1")
    assert await queue.put("REQ-1") is True


@pytest.mark.asyncio
async def test_action_queue_can_remove_pending_item_before_a_consumer_gets_it() -> None:
    queue = ActionQueue()

    await queue.put("REQ-1")
    await queue.acknowledge("REQ-1")

    assert queue.empty() is True
    assert await queue.put("REQ-1") is True
    assert await queue.get() == "REQ-1"
