"""Policy, approval, execution, sanitization, and audit pipeline."""

from __future__ import annotations

import asyncio
import getpass
import json
import logging
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timedelta
from functools import partial
from time import monotonic
from typing import Never

from pydantic import Field, JsonValue, TypeAdapter, ValidationError

from diagnose.audit import AuditLog
from diagnose.config import Configuration
from diagnose.domain import (
    TERMINAL_ACTION_STATES,
    ActionReceipt,
    ActionRecord,
    ActionResult,
    ActionState,
    DiagnoseError,
    DiagnosisState,
    DomainModel,
    ErrorCode,
    ExecutionConstraints,
    ExecutionOperation,
    ExecutionPlan,
    FakeOperation,
    InvalidStateTransition,
    NormalizedError,
    PolicyDecision,
    RiskClass,
    canonical_sha256,
    new_request_id,
    utc_now,
)
from diagnose.executors import Executor
from diagnose.persistence import Database, FinalizedAction, StartActionOutcome, StartActionResult
from diagnose.policy import PolicyEngine
from diagnose.sanitization import Sanitizer
from diagnose.terminal.action_queue import ActionQueue

LOGGER = logging.getLogger(__name__)


class ActionSubmission(DomainModel):
    """Internal request resolved by the server; clients never choose risk or executor."""

    session_id: str = Field(min_length=5, max_length=200)
    target_id: str = Field(min_length=1, max_length=200)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=100)
    reason: str = Field(min_length=1, max_length=2000)
    client_request_id: str = Field(min_length=1, max_length=200)
    operation: ExecutionOperation


RiskClassifier = Callable[[str, ExecutionOperation], RiskClass]
_OPERATION_ADAPTER: TypeAdapter[ExecutionOperation] = TypeAdapter(ExecutionOperation)


def _m0_risk_classifier(tool: str, operation: ExecutionOperation) -> RiskClass:
    if tool == "fake_probe" and isinstance(operation, FakeOperation):
        return RiskClass.READ
    raise DiagnoseError(
        ErrorCode.CAPABILITY_NOT_AVAILABLE,
        "No production target executor is available in milestone M0.",
        next_step="Use control tools or continue the diagnosis manually.",
    )


class ActionService:
    """Own the immutable action lifecycle and one-time local approvals."""

    def __init__(
        self,
        database: Database,
        configuration_provider: Callable[[], Configuration],
        *,
        executors: Mapping[str, Executor] | None = None,
        sanitizer: Sanitizer | None = None,
        audit_log: AuditLog | None = None,
        action_queue: ActionQueue | None = None,
        risk_classifier: RiskClassifier = _m0_risk_classifier,
    ) -> None:
        self.database = database
        self._configuration_provider = configuration_provider
        self._executors = dict(executors or {})
        self.sanitizer = sanitizer or Sanitizer()
        self.audit = audit_log or AuditLog(database, sanitizer=self.sanitizer)
        self.queue = action_queue or ActionQueue()
        self._risk_classifier = risk_classifier
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._cancel_reasons: dict[str, str] = {}
        self._finalizing: set[str] = set()
        self._locks: dict[str, asyncio.Lock] = {}
        self._lifecycle_lock = asyncio.Lock()
        self._closed = False

    async def submit(self, submission: ActionSubmission) -> ActionRecord:
        self._ensure_open()
        submission = self._sanitized_submission(submission)
        configuration = self._configuration_provider()
        session = await self.database.get_session(submission.session_id)
        if session is None or session.state is DiagnosisState.CLOSED:
            raise DiagnoseError(
                ErrorCode.INVALID_ARGUMENT,
                "The diagnosis session does not exist or is closed.",
                next_step="Create a new diagnosis session.",
            )
        target = configuration.target(submission.target_id)
        if target is None:
            raise DiagnoseError(
                ErrorCode.TARGET_NOT_FOUND,
                "The requested logical target does not exist.",
                next_step="Call target_list and select an available target ID.",
            )

        risk = self._risk_classifier(submission.tool, submission.operation)
        executor_name = submission.operation.type
        if executor_name not in self._executors:
            raise DiagnoseError(
                ErrorCode.CAPABILITY_NOT_AVAILABLE,
                "The required executor is not available.",
                next_step="Use a supported capability or continue manually.",
            )

        policy_engine = PolicyEngine(
            configuration.policy_set,
            global_limits=configuration.settings.policy_limits(),
        )
        evaluation = policy_engine.evaluate(
            policy_ref=target.policy_ref,
            target_id=target.id,
            tool=submission.tool,
        )
        now = utc_now()
        timeout = evaluation.limits.approval_timeout_seconds or 300
        request_id = new_request_id()
        receipt = ActionReceipt(
            request_id=request_id,
            session_id=submission.session_id,
            status=ActionState.RECEIVED,
            risk=risk,
            summary=submission.reason,
            tool=submission.tool,
            target_id=submission.target_id,
            created_at=now,
            expires_at=now + timedelta(seconds=timeout),
        )
        # The client request ID is the opaque idempotency key, not part of the
        # operation identity protected by that key.
        payload_hash = canonical_sha256(
            submission.model_dump(
                mode="json",
                by_alias=True,
                exclude={"client_request_id"},
            )
        )

        plan: ExecutionPlan | None = None
        if evaluation.decision is PolicyDecision.ALLOW_WITH_APPROVAL:
            limits = evaluation.limits
            plan = ExecutionPlan(
                request_id=request_id,
                session_id=submission.session_id,
                target_id=submission.target_id,
                tool=submission.tool,
                risk=risk,
                reason=submission.reason,
                executor=executor_name,
                operation=submission.operation,
                constraints=ExecutionConstraints(
                    timeout_seconds=limits.timeout_seconds or 20,
                    max_output_bytes=limits.max_output_bytes or 262_144,
                    max_output_lines=limits.max_lines,
                ),
                policy_version=evaluation.policy_version,
                target_version=configuration.target_version(target.id),
            ).with_calculated_hash()

        initial_transition = (
            ActionState.POLICY_REJECTED if plan is None else ActionState.PENDING_APPROVAL
        )
        initial_detail: dict[str, JsonValue]
        initial_audit_data: dict[str, JsonValue]
        if plan is None:
            initial_detail = {"policyVersion": evaluation.policy_version}
            initial_audit_data = {"policyVersion": evaluation.policy_version}
        else:
            initial_detail = {
                "actionHash": plan.action_hash or "",
                "policyVersion": plan.policy_version,
            }
            initial_audit_data = dict(initial_detail)

        action, created = await self.database.create_action(
            receipt,
            client_request_id=submission.client_request_id,
            payload_hash=payload_hash,
            plan=plan,
            initial_transition=initial_transition,
            initial_transition_detail=initial_detail,
            initial_transition_audit_data=initial_audit_data,
        )
        if not created:
            return action
        if plan is None:
            return action
        await self.queue.put(action.request_id)
        return action

    async def approve(self, request_id: str) -> ActionRecord:
        lock = self._locks.setdefault(request_id, asyncio.Lock())
        async with lock:
            self._ensure_open()
            action = await self._require_action(request_id)
            if action.status is not ActionState.PENDING_APPROVAL:
                return self._raise_for_non_pending(action)
            plan = await self._validated_current_plan(action)
            assert plan.action_hash is not None
            critical = asyncio.create_task(
                self._approve_and_register(request_id, plan),
                name=f"diagnose-approve-{request_id}",
            )
            try:
                return await asyncio.shield(critical)
            except asyncio.CancelledError:
                # Cancellation can arrive after SQLite committed EXECUTING but
                # before the DB call yielded its result. The critical task is
                # shielded so it can register and start the runner. Do not let
                # the caller observe cancellation until that invariant holds.
                while not critical.done():
                    try:
                        await asyncio.shield(critical)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                if not critical.cancelled():
                    try:
                        critical.result()
                    except Exception:
                        LOGGER.exception(
                            "Approval critical section failed for request %s",
                            request_id,
                        )
                raise

    async def _approve_and_register(
        self,
        request_id: str,
        plan: ExecutionPlan,
    ) -> ActionRecord:
        """Atomically start an action and install its in-process runner."""

        assert plan.action_hash is not None
        # Closing and starting share one short critical section. Once the
        # SQLite CAS commits EXECUTING, close() is guaranteed to see and cancel
        # the registered task before it can return.
        async with self._lifecycle_lock:
            self._ensure_open()
            started = await self.database.approve_and_start_action(
                request_id,
                plan.action_hash,
                at=utc_now(),
                approver=self._local_approver(),
                precondition=self._approval_precondition,
            )
            if started.outcome is not StartActionOutcome.STARTED:
                await self.queue.acknowledge(request_id)
                self._raise_for_start_failure(started)

            assert started.action is not None
            assert started.plan is not None
            assert started.action.started_at is not None
            cancel_event = asyncio.Event()
            task_ready = asyncio.Event()
            self._cancel_events[request_id] = cancel_event
            task = asyncio.create_task(
                self._execute(
                    started.plan,
                    cancel_event,
                    started.action.started_at,
                    task_ready,
                ),
                name=f"diagnose-action-{request_id}",
            )
            self._tasks[request_id] = task
            task.add_done_callback(partial(self._task_finished, request_id))
            # A task cancelled before its coroutine starts cannot run its
            # cancellation finalizer. Keep close() outside this section until
            # the runner has entered its protected body.
            await task_ready.wait()
            await self.queue.acknowledge(request_id)
            return started.action

    async def reject(self, request_id: str, reason: str | None = None) -> ActionRecord:
        lock = self._locks.setdefault(request_id, asyncio.Lock())
        async with lock:
            await self.database.expire_actions()
            action = await self._require_action(request_id)
            if action.status is not ActionState.PENDING_APPROVAL:
                return self._raise_for_non_pending(action)
            action = await self.database.transition_action(
                request_id,
                ActionState.REJECTED,
                detail={"reason": reason or "Rejected by the local approver."},
                audit_event_type="action.rejected",
                audit_data={"reason": reason or "Rejected by the local approver."},
            )
            await self.queue.acknowledge(request_id)
            return action

    async def cancel(self, request_id: str, reason: str | None = None) -> ActionRecord:
        lock = self._locks.setdefault(request_id, asyncio.Lock())
        async with lock:
            cancel_reason = reason or "Cancellation requested."
            action = await self._require_action(request_id)
            if action.status in TERMINAL_ACTION_STATES:
                return action
            if action.status is ActionState.PENDING_APPROVAL:
                action = await self.database.transition_action(
                    request_id,
                    ActionState.CANCELLED,
                    detail={"reason": cancel_reason},
                    audit_event_type="action.cancelled",
                    audit_data={"reason": cancel_reason},
                )
                await self.queue.acknowledge(request_id)
            elif action.status is ActionState.EXECUTING:
                self._cancel_reasons.setdefault(request_id, cancel_reason)
                event = self._cancel_events.get(request_id)
                if event is not None:
                    event.set()
                task = self._tasks.get(request_id)
                if task is not None:
                    if (
                        request_id not in self._finalizing
                        and not task.done()
                        and task.cancelling() == 0
                    ):
                        task.cancel()
                    with suppress(asyncio.CancelledError):
                        await task
                else:
                    latest = await self._require_action(request_id)
                    if latest.status is ActionState.EXECUTING:
                        await self._finalize_interrupted_action(latest, cancel_reason)
                action = await self._require_action(request_id)
            else:
                raise DiagnoseError(
                    ErrorCode.CANCELLED,
                    f"Action cannot be cancelled while it is {action.status.value}.",
                )
            return action

    async def pending_ids(self) -> list[str]:
        await self.database.expire_actions()
        actions = await self.database.list_actions(state=ActionState.PENDING_APPROVAL, limit=1000)
        return [action.request_id for action in actions]

    async def render_plan(self, request_id: str) -> str:
        plan = await self.database.load_execution_plan(request_id)
        if plan is None:
            raise DiagnoseError(ErrorCode.INVALID_ARGUMENT, "Execution plan was not found.")
        operation = json.dumps(
            plan.operation.model_dump(mode="json", by_alias=True),
            indent=2,
            ensure_ascii=False,
        )
        rendered = (
            f"Request: {plan.request_id}\n"
            f"Session: {plan.session_id}\n"
            f"Target: {plan.target_id}\n"
            f"Tool: {plan.tool}\n"
            f"Risk: {plan.risk.value}\n"
            f"Reason: {plan.reason}\n\n"
            f"Resolved operation:\n{operation}\n\n"
            f"Timeout: {plan.constraints.timeout_seconds} s\n"
            f"Maximum output: {plan.constraints.max_output_bytes} bytes\n"
            f"Policy: {plan.policy_version}\n"
            f"Target version: {plan.target_version}\n"
            f"Hash: {plan.action_hash}"
        )
        # Plans are sanitized before persistence. This second pass is defense in
        # depth for values that may have been written by an older installation.
        return self.sanitizer.sanitize_text(rendered)[0]

    async def status(self, request_id: str) -> ActionRecord:
        await self.database.expire_actions()
        return await self._require_action(request_id)

    async def result(self, request_id: str) -> ActionResult | None:
        await self._require_action(request_id)
        return await self.database.get_result(request_id)

    async def history(self, session_id: str, *, limit: int = 100) -> list[ActionRecord]:
        return await self.database.list_actions(session_id=session_id, limit=limit)

    async def close(self) -> None:
        async with self._lifecycle_lock:
            if self._closed and not self._tasks:
                return
            self._closed = True
            active = list(self._tasks.items())
        for request_id, _task in active:
            self._cancel_reasons.setdefault(request_id, "Terminal Server is stopping.")
        for event in list(self._cancel_events.values()):
            event.set()
        for _request_id, task in active:
            if _request_id not in self._finalizing and not task.done() and task.cancelling() == 0:
                task.cancel()
        if active:
            await asyncio.gather(*(task for _, task in active), return_exceptions=True)

    def _sanitized_submission(self, submission: ActionSubmission) -> ActionSubmission:
        """Remove secrets/control sequences before hashing or persisting a plan."""

        reason, _ = self.sanitizer.sanitize_text(submission.reason)
        sanitized_operation = self.sanitizer.sanitize(submission.operation)
        if not isinstance(sanitized_operation.data, dict):
            raise DiagnoseError(
                ErrorCode.INVALID_ARGUMENT,
                "The resolved operation exceeds the safe input limits.",
                next_step="Submit a smaller operation without inline credentials.",
            )
        try:
            operation = _OPERATION_ADAPTER.validate_python(sanitized_operation.data)
            values = submission.model_dump(mode="python", by_alias=False)
            values.update({"reason": reason, "operation": operation})
            return ActionSubmission.model_validate(values)
        except ValidationError as exc:
            raise DiagnoseError(
                ErrorCode.INVALID_ARGUMENT,
                "The resolved operation is invalid after security sanitization.",
                next_step="Remove inline credentials and submit a valid operation.",
            ) from exc

    async def _validated_current_plan(self, action: ActionRecord) -> ExecutionPlan:
        try:
            plan = await self.database.load_execution_plan(action.request_id)
        except ValueError as exc:
            await self._expire_pending(action, "plan_integrity_failure")
            raise DiagnoseError(
                ErrorCode.APPROVAL_EXPIRED,
                "The persisted execution plan failed integrity verification.",
                next_step="Submit a new action and review it again.",
            ) from exc
        if plan is None or not plan.verify_hash():
            await self._expire_pending(action, "plan_missing_or_invalid")
            raise DiagnoseError(
                ErrorCode.APPROVAL_EXPIRED,
                "The execution plan is missing or invalid.",
                next_step="Submit a new action and review it again.",
            )
        configuration = self._configuration_provider()
        target = configuration.target(plan.target_id)
        if target is None:
            await self._expire_pending(action, "target_removed")
            raise DiagnoseError(
                ErrorCode.APPROVAL_EXPIRED,
                "The target changed after the action was submitted.",
                next_step="Submit a new action against the current target.",
            )
        evaluation = PolicyEngine(
            configuration.policy_set,
            global_limits=configuration.settings.policy_limits(),
        ).evaluate(policy_ref=target.policy_ref, target_id=target.id, tool=plan.tool)
        current_target_version = configuration.target_version(target.id)
        if (
            not evaluation.allowed
            or evaluation.policy_version != plan.policy_version
            or current_target_version != plan.target_version
        ):
            await self._expire_pending(action, "policy_or_target_changed")
            raise DiagnoseError(
                ErrorCode.APPROVAL_EXPIRED,
                "Policy or target configuration changed after submission.",
                next_step="Submit a new action and review the updated plan.",
            )
        if plan.executor not in self._executors:
            await self._expire_pending(action, "executor_unavailable")
            raise DiagnoseError(
                ErrorCode.APPROVAL_EXPIRED,
                "The approved executor is no longer available.",
                next_step="Submit a new action after restoring the target capability.",
            )
        return plan

    def _approval_precondition(self, plan: ExecutionPlan) -> bool:
        """Revalidate mutable configuration at the DB approval linearization point.

        This callback is deliberately synchronous: Database invokes it while
        holding its write lock and transaction immediately before the approval
        state transition. Any loading or validation failure denies approval.
        """

        try:
            configuration = self._configuration_provider()
            target = configuration.target(plan.target_id)
            if target is None:
                return False
            evaluation = PolicyEngine(
                configuration.policy_set,
                global_limits=configuration.settings.policy_limits(),
            ).evaluate(policy_ref=target.policy_ref, target_id=target.id, tool=plan.tool)
            return (
                evaluation.allowed
                and evaluation.policy_version == plan.policy_version
                and configuration.target_version(target.id) == plan.target_version
                and plan.executor in self._executors
            )
        except Exception:
            LOGGER.warning(
                "Approval precondition failed closed for request %s",
                plan.request_id,
                exc_info=True,
            )
            return False

    async def _execute(
        self,
        plan: ExecutionPlan,
        cancel_event: asyncio.Event,
        started: datetime,
        task_ready: asyncio.Event,
    ) -> None:
        start_clock = monotonic()
        task_ready.set()
        try:
            executor = self._executors[plan.executor]
            async with asyncio.timeout(plan.constraints.timeout_seconds):
                output = await executor.execute(plan, cancel_event)
            raw_output = {
                "data": output.data,
                "warnings": list(output.warnings),
                "exitCode": output.exit_code,
            }
            sanitized = self.sanitizer.sanitize(
                raw_output,
                max_output_bytes=plan.constraints.max_output_bytes,
                max_output_lines=plan.constraints.max_output_lines,
            )
            safe = (
                sanitized.data if isinstance(sanitized.data, dict) else {"output": sanitized.data}
            )
            warning_items = safe.get("warnings")
            warnings = (
                [str(item) for item in warning_items] if isinstance(warning_items, list) else []
            )
            result = ActionResult(
                request_id=plan.request_id,
                status=ActionState.COMPLETED,
                tool=plan.tool,
                target_id=plan.target_id,
                started_at=started,
                finished_at=utc_now(),
                duration_ms=max(0, int((monotonic() - start_clock) * 1000)),
                data=safe.get("data"),
                warnings=warnings,
                redactions=sanitized.redactions,
                truncated=sanitized.truncated,
            )
            finalized = await self._durable_finalize(
                result,
                audit_data={"actionHash": plan.action_hash or ""},
            )
            action = finalized.action
        except asyncio.CancelledError:
            reason = self._cancel_reasons.get(plan.request_id, "Execution was cancelled.")
            action = await self._finish_execution_error(
                plan,
                ActionState.CANCELLED,
                ErrorCode.CANCELLED,
                "Execution was cancelled.",
                started,
                start_clock,
                audit_data={"reason": reason},
            )
        except TimeoutError:
            action = await self._finish_execution_error(
                plan,
                ActionState.FAILED,
                ErrorCode.TIMEOUT,
                "Execution exceeded its approved timeout.",
                started,
                start_clock,
                audit_data={"reason": "approved_timeout_exceeded"},
            )
        except Exception:
            LOGGER.exception("Executor failed for request %s", plan.request_id)
            action = await self._finish_execution_error(
                plan,
                ActionState.FAILED,
                ErrorCode.EXECUTION_FAILED,
                "The approved operation failed.",
                started,
                start_clock,
                audit_data={"reason": "executor_failure"},
            )
        LOGGER.debug("Action %s finalized as %s", action.request_id, action.status.value)

    async def _finish_execution_error(
        self,
        plan: ExecutionPlan,
        state: ActionState,
        code: ErrorCode,
        message: str,
        started: datetime,
        start_clock: float,
        *,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> ActionRecord:
        error = NormalizedError(code=code, message=message)
        result = ActionResult(
            request_id=plan.request_id,
            status=state,
            tool=plan.tool,
            target_id=plan.target_id,
            started_at=started,
            finished_at=utc_now(),
            duration_ms=max(0, int((monotonic() - start_clock) * 1000)),
            error=error,
        )
        safe_audit_data: dict[str, JsonValue] = {"actionHash": plan.action_hash or ""}
        safe_audit_data.update(audit_data or {})
        finalized = await self._durable_finalize(result, audit_data=safe_audit_data)
        return finalized.action

    async def _finalize_interrupted_action(
        self,
        action: ActionRecord,
        reason: str,
    ) -> ActionRecord:
        """Finalize an EXECUTING row that has no in-process runner."""

        if action.status is not ActionState.EXECUTING:
            return action
        finished = utc_now()
        duration_ms = (
            max(0, int((finished - action.started_at).total_seconds() * 1000))
            if action.started_at is not None
            else 0
        )
        result = ActionResult(
            request_id=action.request_id,
            status=ActionState.CANCELLED,
            tool=action.tool,
            target_id=action.target_id,
            started_at=action.started_at,
            finished_at=finished,
            duration_ms=duration_ms,
            error=NormalizedError(code=ErrorCode.CANCELLED, message="Execution was cancelled."),
        )
        finalized = await self._durable_finalize(result, audit_data={"reason": reason})
        return finalized.action

    async def _durable_finalize(
        self,
        result: ActionResult,
        *,
        audit_data: dict[str, JsonValue] | None = None,
    ) -> FinalizedAction:
        """Mark the SQLite commit phase so shutdown never cancels it mid-transaction."""

        self._finalizing.add(result.request_id)
        try:
            return await self.database.finalize_action(result, audit_data=audit_data)
        finally:
            self._finalizing.discard(result.request_id)

    async def _expire_pending(self, action: ActionRecord, reason: str) -> ActionRecord:
        """Expire a reviewed plan and commit its audit record with the transition."""

        try:
            return await self.database.transition_action(
                action.request_id,
                ActionState.EXPIRED,
                detail={"reason": reason},
                audit_event_type="action.expired",
                audit_data={"reason": reason},
            )
        except InvalidStateTransition:
            # Another local lifecycle call won the terminal transition. Never
            # manufacture a second event or overwrite its result.
            return await self._require_action(action.request_id)

    async def _require_action(self, request_id: str) -> ActionRecord:
        action = await self.database.get_action(request_id)
        if action is None:
            raise DiagnoseError(
                ErrorCode.INVALID_ARGUMENT,
                "The action request ID does not exist.",
                next_step="Call action_history for the current session.",
            )
        return action

    def _raise_for_non_pending(self, action: ActionRecord) -> Never:
        if action.status is ActionState.REJECTED:
            code = ErrorCode.APPROVAL_REJECTED
        elif action.status is ActionState.EXPIRED:
            code = ErrorCode.APPROVAL_EXPIRED
        else:
            code = ErrorCode.INVALID_ARGUMENT
        raise DiagnoseError(code, f"Action is {action.status.value} and cannot be approved.")

    def _raise_for_start_failure(self, result: StartActionResult) -> Never:
        if result.outcome is StartActionOutcome.NON_PENDING and result.action is not None:
            self._raise_for_non_pending(result.action)
        error = result.error or NormalizedError(
            code=ErrorCode.INTERNAL_ERROR,
            message="The action could not be started atomically.",
        )
        raise DiagnoseError(
            error.code,
            error.message,
            next_step=error.next_step,
            retryable=error.retryable,
        )

    def _ensure_open(self) -> None:
        if self._closed:
            raise DiagnoseError(
                ErrorCode.CANCELLED,
                "The local approval service is stopping.",
                next_step="Start the Terminal Server and submit the request again.",
            )

    def _local_approver(self) -> str:
        """Resolve local OS identity; no remotely supplied identity is accepted."""

        try:
            candidate = getpass.getuser()
        except (OSError, KeyError):
            candidate = ""
        identity, _ = self.sanitizer.sanitize_text(candidate)
        return identity.strip()[:100] or "local-user"

    def _task_finished(self, request_id: str, task: asyncio.Task[None]) -> None:
        self._tasks.pop(request_id, None)
        self._cancel_events.pop(request_id, None)
        self._cancel_reasons.pop(request_id, None)
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            LOGGER.error(
                "Action task %s terminated before durable finalization",
                request_id,
                exc_info=(type(error), error, error.__traceback__),
            )
