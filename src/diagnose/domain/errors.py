"""Stable normalized error contracts."""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from .base import DomainModel


class ErrorCode(StrEnum):
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
    CAPABILITY_NOT_AVAILABLE = "CAPABILITY_NOT_AVAILABLE"
    POLICY_DENIED = "POLICY_DENIED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    TERMINAL_SERVER_OFFLINE = "TERMINAL_SERVER_OFFLINE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    HOST_KEY_MISMATCH = "HOST_KEY_MISMATCH"
    CONNECTION_FAILED = "CONNECTION_FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    READ_ONLY_VIOLATION = "READ_ONLY_VIOLATION"
    PROTOCOL_VERSION_MISMATCH = "PROTOCOL_VERSION_MISMATCH"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class NormalizedError(DomainModel):
    code: ErrorCode
    message: str = Field(min_length=1, max_length=1000)
    next_step: str | None = Field(default=None, min_length=1, max_length=1000)
    retryable: bool = False


class DiagnoseError(Exception):
    """Exception wrapper whose public form is safe to serialize."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        next_step: str | None = None,
        retryable: bool = False,
    ) -> None:
        self.error = NormalizedError(
            code=code,
            message=message,
            next_step=next_step,
            retryable=retryable,
        )
        super().__init__(message)


class IdempotencyConflict(DiagnoseError):
    def __init__(self) -> None:
        super().__init__(
            ErrorCode.INVALID_ARGUMENT,
            "clientRequestId was already used with a different payload",
            next_step="Generate a new clientRequestId for the changed request.",
        )
