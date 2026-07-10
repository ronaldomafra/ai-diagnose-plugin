from __future__ import annotations

from diagnose.sanitization import REDACTED, TRUNCATED, Sanitizer


def _embedded_newlines(value: object) -> int:
    if isinstance(value, str):
        return value.count("\n")
    if isinstance(value, dict):
        return sum(
            _embedded_newlines(key) + _embedded_newlines(item) for key, item in value.items()
        )
    if isinstance(value, list):
        return sum(_embedded_newlines(item) for item in value)
    return 0


def test_common_environment_secret_fields_are_normalized_and_redacted() -> None:
    result = Sanitizer().sanitize(
        {
            "DATABASE_URL": "postgresql://alice:db-secret@db/app",
            "aws-secret-access-key": "aws-secret",
            "Secret Key": "application-secret",
        }
    )

    assert result.data == {
        "DATABASE_URL": REDACTED,
        "aws-secret-access-key": REDACTED,
        "Secret Key": REDACTED,
    }
    assert set(result.redactions) == {
        "awssecretaccesskey",
        "databaseurl",
        "secretkey",
    }


def test_uri_userinfo_and_quoted_credentials_with_spaces_are_redacted() -> None:
    value = (
        "password = \"open sesame\"; secret_key: '  signing secret  '; "
        "connect=https://alice:p%40ss@example.test/resource"
    )

    result, redactions = Sanitizer().sanitize_text(value)

    assert "open sesame" not in result
    assert "signing secret" not in result
    assert "alice" not in result
    assert "p%40ss" not in result
    assert f"https://{REDACTED}@example.test/resource" in result
    assert {"credential", "uri-userinfo"} <= set(redactions)


def test_untrusted_field_and_pattern_names_never_leak_in_redaction_metadata() -> None:
    field_name = "tenant-42-credential-name"
    pattern_name = "metadata-password=do-not-echo\x1b]0;spoof\x07"
    sanitizer = Sanitizer(
        sensitive_fields=[field_name],
        patterns={pattern_name: r"visible-secret"},
    )

    result = sanitizer.sanitize({field_name: "value", "message": "visible-secret"})

    assert result.data == {field_name: REDACTED, "message": REDACTED}
    assert result.redactions == ["custom-pattern", "sensitive-field"]
    metadata = " ".join(result.redactions)
    assert field_name not in metadata
    assert "do-not-echo" not in metadata
    assert "\x1b" not in metadata


def test_line_limit_counts_newlines_inside_structured_values() -> None:
    result = Sanitizer(max_output_lines=2).sanitize(
        {
            "message": "one\ntwo\nthree",
            "nested\nkey": ["four\nfive"],
        }
    )

    assert isinstance(result.data, dict)
    assert result.truncated
    assert _embedded_newlines(result.data) <= 1
    assert TRUNCATED in str(result.data)


def test_structured_json_shape_is_preserved_when_within_limits() -> None:
    value = {"message": "one\ntwo", "nested": [1, True, None]}

    result = Sanitizer(max_output_lines=3).sanitize(value)

    assert result.data == value
    assert not result.truncated


def test_carriage_returns_cannot_overwrite_sanitized_output() -> None:
    result = Sanitizer().sanitize("approved\rDENIED\r\nnext")

    assert result.data == "approvedDENIED\nnext"
    assert "\r" not in str(result.data)
