"""Output redaction, terminal-escape removal, and bounded truncation."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from re import Pattern
from typing import Any

from pydantic import BaseModel

from .models import SanitizedValue

REDACTED = "[REDACTED]"
TRUNCATED = "...[TRUNCATED]"

# OSC includes terminal-title and hyperlink sequences terminated by BEL or ST.
_OSC_RE = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?")
_CSI_RE = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")
_DCS_RE = re.compile(r"\x1b[P^_].*?\x1b\\", re.DOTALL)
_ESC_RE = re.compile(r"\x1b[@-_]")
_DANGEROUS_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

DEFAULT_SENSITIVE_FIELDS = frozenset(
    {
        "authorization",
        "awssecretaccesskey",
        "proxyauthorization",
        "cookie",
        "databaseurl",
        "dbpassword",
        "setcookie",
        "password",
        "passwd",
        "pwd",
        "secret",
        "clientsecret",
        "token",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "privatekey",
        "secretkey",
        "connectionstring",
    }
)

_DEFAULT_PATTERNS: dict[str, Pattern[str]] = {
    "authorization": re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "credential": re.compile(
        r"(?i)\b(password|passwd|pwd|token|api[\s_-]*key|client[\s_-]*secret|"
        r"secret[\s_-]*key|aws[\s_-]*secret[\s_-]*access[\s_-]*key|"
        r"database[\s_-]*url)"
        r"(\s*[:=]\s*)"
        r"""("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;]+)"""
    ),
    "cookie": re.compile(r"(?im)\b(set-cookie|cookie)(\s*:\s*)([^\r\n]*)"),
    "private-key": re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?"
        r"-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
        re.DOTALL,
    ),
    "uri-userinfo": re.compile(
        r"(?i)(\b[a-z][a-z0-9+.-]*://)([^/@\s]+)@",
    ),
}

_TRUSTED_PATTERN_LABELS = frozenset(_DEFAULT_PATTERNS)
_SENSITIVE_SUFFIX_LABELS = (
    ("password", "password"),
    ("passwd", "passwd"),
    ("token", "token"),
    ("secretkey", "secretkey"),
    ("secret", "secret"),
    ("privatekey", "privatekey"),
    ("apikey", "apikey"),
)


def strip_terminal_sequences(value: str) -> str:
    """Remove ANSI/OSC/DCS and unsafe control characters from untrusted text."""

    # CR can move the cursor to the beginning of a line and visually replace an
    # approval detail. Preserve CRLF's line break while dropping bare CR.
    value = value.replace("\r\n", "\n").replace("\r", "")
    value = _OSC_RE.sub("", value)
    value = _DCS_RE.sub("", value)
    value = _CSI_RE.sub("", value)
    value = _ESC_RE.sub("", value)
    return _DANGEROUS_CONTROL_RE.sub("", value)


def truncate_utf8(value: str, max_bytes: int, *, marker: str = TRUNCATED) -> tuple[str, bool]:
    """Truncate without splitting a UTF-8 codepoint, always honoring max_bytes."""

    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    marker_bytes = marker.encode("utf-8")
    if max_bytes <= len(marker_bytes):
        return marker_bytes[:max_bytes].decode("utf-8", errors="ignore"), True
    prefix = encoded[: max_bytes - len(marker_bytes)].decode("utf-8", errors="ignore")
    return prefix + marker, True


def truncate_lines(value: str, max_lines: int) -> tuple[str, bool]:
    lines = value.splitlines(keepends=True)
    if len(lines) <= max_lines:
        return value, False
    # Keep the marker on the final permitted line so the result itself never
    # exceeds max_lines.
    return "".join(lines[:max_lines]).rstrip("\r\n") + TRUNCATED, True


def _serialized(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def _normalize_field(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


class Sanitizer:
    def __init__(
        self,
        *,
        sensitive_fields: Sequence[str] = (),
        patterns: Mapping[str, str | Pattern[str]] | None = None,
        max_input_bytes: int = 16 * 1024 * 1024,
        max_output_bytes: int = 8 * 1024 * 1024,
        max_output_lines: int = 100_000,
    ) -> None:
        if min(max_input_bytes, max_output_bytes, max_output_lines) < 1:
            raise ValueError("sanitization limits must be positive")
        self.sensitive_fields = DEFAULT_SENSITIVE_FIELDS | {
            _normalize_field(field) for field in sensitive_fields
        }
        self.patterns = dict(_DEFAULT_PATTERNS)
        self._pattern_labels = {label: label for label in self.patterns}
        for label, pattern in (patterns or {}).items():
            try:
                self.patterns[label] = re.compile(pattern) if isinstance(pattern, str) else pattern
            except re.error as exc:
                raise ValueError(f"invalid redaction pattern {label!r}") from exc
            # Pattern names are caller-controlled metadata. Never echo one into
            # results unless it is one of our fixed, non-secret labels.
            self._pattern_labels[label] = (
                label if label in _TRUSTED_PATTERN_LABELS else "custom-pattern"
            )
        self.max_input_bytes = max_input_bytes
        self.max_output_bytes = max_output_bytes
        self.max_output_lines = max_output_lines

    def sanitize(
        self,
        value: Any,
        *,
        max_input_bytes: int | None = None,
        max_output_bytes: int | None = None,
        max_output_lines: int | None = None,
    ) -> SanitizedValue:
        input_limit = min(max_input_bytes or self.max_input_bytes, self.max_input_bytes)
        output_limit = min(max_output_bytes or self.max_output_bytes, self.max_output_bytes)
        line_limit = min(max_output_lines or self.max_output_lines, self.max_output_lines)
        original_text = _serialized(self._json_compatible(value))
        original_bytes = len(original_text.encode("utf-8"))
        redactions: set[str] = set()
        pre_truncated = original_bytes > input_limit

        if pre_truncated and not isinstance(value, str):
            # Do not partially serialize a structured secret-bearing value. An
            # explicit omission is safer than returning a malformed fragment.
            sanitized: Any = f"[INPUT OMITTED: exceeds {input_limit} bytes]"
        else:
            if isinstance(value, str) and pre_truncated:
                value, _ = truncate_utf8(value, input_limit)
            sanitized = self._walk(value, redactions, depth=0)

        if isinstance(sanitized, str):
            sanitized, lines_truncated = truncate_lines(sanitized, line_limit)
            sanitized, bytes_truncated = truncate_utf8(sanitized, output_limit)
        else:
            sanitized, lines_truncated = self._truncate_structured_lines(
                sanitized,
                line_limit,
            )
            rendered = _serialized(sanitized)
            rendered, bytes_truncated = truncate_utf8(rendered, output_limit)
            if bytes_truncated:
                # A truncated JSON object is not valid JSON; return bounded text.
                sanitized = rendered

        returned_bytes = len(_serialized(sanitized).encode("utf-8"))
        return SanitizedValue(
            data=sanitized,
            redactions=sorted(redactions),
            truncated=pre_truncated or lines_truncated or bytes_truncated,
            original_bytes=original_bytes,
            returned_bytes=returned_bytes,
        )

    def sanitize_text(self, value: str) -> tuple[str, list[str]]:
        redactions: set[str] = set()
        return self._sanitize_string(value, redactions), sorted(redactions)

    def _walk(self, value: Any, redactions: set[str], *, depth: int) -> Any:
        if depth > 100:
            return "[OMITTED: nesting limit]"
        if isinstance(value, BaseModel):
            value = value.model_dump(mode="json", by_alias=True)
        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for raw_key, item in value.items():
                key = self._sanitize_string(str(raw_key), redactions)
                normalized = _normalize_field(key)
                if self._is_sensitive_field(normalized):
                    result[key] = REDACTED
                    redactions.add(self._field_redaction_label(normalized))
                else:
                    result[key] = self._walk(item, redactions, depth=depth + 1)
            return result
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._walk(item, redactions, depth=depth + 1) for item in value]
        if isinstance(value, bytes):
            return self._sanitize_string(value.decode("utf-8", errors="replace"), redactions)
        if isinstance(value, str):
            return self._sanitize_string(value, redactions)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return self._sanitize_string(str(value), redactions)

    def _sanitize_string(self, value: str, redactions: set[str]) -> str:
        result = strip_terminal_sequences(value)
        for label, pattern in self.patterns.items():
            if label in {"credential", "cookie"}:
                result, count = pattern.subn(
                    lambda match: match.group(1) + match.group(2) + REDACTED,
                    result,
                )
            elif label == "uri-userinfo":
                result, count = pattern.subn(
                    lambda match: match.group(1) + REDACTED + "@",
                    result,
                )
            else:
                result, count = pattern.subn(REDACTED, result)
            if count:
                redactions.add(self._pattern_labels[label])
        return result

    def _is_sensitive_field(self, normalized: str) -> bool:
        if normalized in self.sensitive_fields:
            return True
        # Common names are frequently prefixed (dbPassword, githubToken).
        return any(normalized.endswith(suffix) for suffix, _label in _SENSITIVE_SUFFIX_LABELS)

    def _field_redaction_label(self, normalized: str) -> str:
        """Return only bounded, controlled metadata for a sensitive field."""

        if normalized in DEFAULT_SENSITIVE_FIELDS:
            return normalized
        for suffix, label in _SENSITIVE_SUFFIX_LABELS:
            if normalized.endswith(suffix):
                return label
        return "sensitive-field"

    def _truncate_structured_lines(self, value: Any, max_lines: int) -> tuple[Any, bool]:
        """Bound embedded newlines without destroying the JSON value shape."""

        remaining_newlines = max_lines - 1
        truncated = False

        def visit(item: Any) -> Any:
            nonlocal remaining_newlines, truncated
            if isinstance(item, str):
                newline_count = item.count("\n")
                if newline_count <= remaining_newlines:
                    remaining_newlines -= newline_count
                    return item
                truncated = True
                if remaining_newlines == 0:
                    return item.partition("\n")[0] + TRUNCATED
                parts = item.split("\n", maxsplit=remaining_newlines + 1)
                kept = "\n".join(parts[: remaining_newlines + 1])
                remaining_newlines = 0
                return kept + TRUNCATED
            if isinstance(item, Mapping):
                return {visit(key): visit(child) for key, child in item.items()}
            if isinstance(item, list):
                return [visit(child) for child in item]
            return item

        return visit(value), truncated

    def _json_compatible(self, value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json", by_alias=True)
        if isinstance(value, Mapping):
            return {str(key): self._json_compatible(item) for key, item in value.items()}
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [self._json_compatible(item) for item in value]
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value


def sanitize(value: Any, **kwargs: Any) -> SanitizedValue:
    """Convenience entry point using secure defaults."""

    return Sanitizer().sanitize(value, **kwargs)
