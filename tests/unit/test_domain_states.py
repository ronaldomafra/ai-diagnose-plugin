import pytest

from diagnose.domain import (
    ACTION_TRANSITIONS,
    ActionState,
    InvalidStateTransition,
    can_transition,
    require_transition,
)


def test_only_documented_action_transitions_are_accepted() -> None:
    assert can_transition(ActionState.RECEIVED, ActionState.PENDING_APPROVAL)
    assert can_transition(ActionState.PENDING_APPROVAL, ActionState.APPROVED)
    assert can_transition(ActionState.APPROVED, ActionState.EXECUTING)
    assert can_transition(ActionState.EXECUTING, ActionState.COMPLETED)
    assert not can_transition(ActionState.PENDING_APPROVAL, ActionState.EXECUTING)
    assert not ACTION_TRANSITIONS[ActionState.COMPLETED]

    with pytest.raises(InvalidStateTransition):
        require_transition(ActionState.COMPLETED, ActionState.EXECUTING)
