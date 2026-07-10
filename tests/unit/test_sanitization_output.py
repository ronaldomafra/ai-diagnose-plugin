from diagnose.sanitization import REDACTED, TRUNCATED, Sanitizer, strip_terminal_sequences


def test_field_and_pattern_redaction_are_recursive() -> None:
    result = Sanitizer().sanitize(
        {
            "authorization": "Bearer very-secret",
            "nested": {
                "dbPassword": "secret",
                "message": "token=another-secret normal evidence",
            },
        }
    )

    assert result.data == {
        "authorization": REDACTED,
        "nested": {
            "dbPassword": REDACTED,
            "message": f"token={REDACTED} normal evidence",
        },
    }
    assert {"authorization", "dbpassword", "credential"} <= set(result.redactions)


def test_ansi_osc_and_dangerous_controls_are_removed() -> None:
    text = "\x1b[31mERROR\x1b[0m \x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07\x00"

    clean = strip_terminal_sequences(text)

    assert clean == "ERROR click"
    assert "\x1b" not in clean


def test_cookie_headers_are_masked_in_unstructured_text() -> None:
    clean, redactions = Sanitizer().sanitize_text(
        "Set-Cookie: session=secret; HttpOnly\nstatus=healthy"
    )

    assert clean == f"Set-Cookie: {REDACTED}\nstatus=healthy"
    assert "cookie" in redactions


def test_byte_and_line_truncation_are_explicit_and_utf8_safe() -> None:
    result = Sanitizer(max_output_bytes=48, max_output_lines=2).sanitize(
        "áááááá\nsecond line\nthird line"
    )

    assert result.truncated
    assert TRUNCATED in str(result.data)
    assert result.returned_bytes <= 48


def test_oversized_structured_input_is_omitted_without_secret_leakage() -> None:
    result = Sanitizer(max_input_bytes=20).sanitize({"password": "x" * 100})

    assert result.truncated
    assert "x" * 20 not in str(result.data)
