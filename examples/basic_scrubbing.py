"""
examples/basic_scrubbing.py — Minimal example of mcp_patterns PII scrubbing.

Run:
    python examples/basic_scrubbing.py
"""
from __future__ import annotations

import hashlib
import logging

from mcp_patterns import (
    FailClosedScrubber,
    PIIScrubber,
    scrub_pii,
    scrub_pii_field,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)


def demo_text_scrubbing() -> None:
    print("\n--- Tier 1: Free-text scrubbing ---")

    examples = [
        "Contact alice@example.com about the Q2 contract.",
        "Card number: 4111 1111 1111 1111, SSN: 123-45-6789",
        "Call support at 415-555-0100 or +1 800 555 0199",
        "AWS key: AKIAIOSFODNN7EXAMPLE123 do not share",
        "password=hunter2 was used in the test run",
        "No sensitive data here — just plain text.",
    ]

    for text in examples:
        scrubbed, detected = scrub_pii(text)
        label = f"[{', '.join(detected)}]" if detected else "[none]"
        print(f"  IN : {text}")
        print(f"  OUT: {scrubbed}  detected={label}")
        print()


def demo_field_scrubbing() -> None:
    print("\n--- Tier 2: Field-semantic scrubbing ---")

    fields = [
        ("email",        "alice@example.com"),
        ("email_address","BOB@CORP.COM"),
        ("token",        "mnemo_token_abcd1234efgh5678"),
        ("session_token","sess_xxxxxxxxxABCD"),
        ("jwt",          "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"),
        ("password",     "super-secret-password"),
        ("pwd",          "another-password"),
        ("api_key",      "sk_live_abc123def456"),
        ("secret",       "some-secret-value"),
        ("access_key",   "AKIAIOSFODNN7EXAMPLE"),
        ("project_name", "Q2 Roadmap"),
        ("project",      "Internal Strategy"),
        ("description",  "Reviewed the hiring plan (unchanged)"),
        ("count",        42),
    ]

    for field_type, value in fields:
        result = scrub_pii_field(field_type, value)
        print(f"  {field_type:<20} {str(value)!r:<45} → {result!r}")


def demo_pii_scrubber_class() -> None:
    print("\n--- PIIScrubber class with custom patterns ---")
    import re

    scrubber = PIIScrubber(
        extra_patterns=[
            ("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]"),
        ],
        extra_drop_fields=frozenset({"internal_secret"}),
    )

    text = "Employee EMP-001234 has email alice@example.com"
    scrubbed, detected = scrubber.scrub_text(text)
    print(f"  IN : {text}")
    print(f"  OUT: {scrubbed}")
    print(f"  detected: {detected}")

    safe = scrubber.scrub_field("internal_secret", "top-secret-token")
    print(f"\n  scrub_field('internal_secret', ...) → {safe!r}  (custom drop field)")

    record = {
        "email":           "alice@corp.com",
        "token":           "tok_abcd1234",
        "project_name":    "Moonshot",
        "password":        "s3cr3t",
        "internal_secret": "classified",
        "note":            "Normal text",
    }
    safe_record = scrubber.scrub_record(record)
    print(f"\n  scrub_record input:  {record}")
    print(f"  scrub_record output: {safe_record}")


def demo_fail_closed() -> None:
    print("\n--- FailClosedScrubber — fail-closed write policy ---")

    scrubber = FailClosedScrubber()
    writes_attempted: list[str] = []

    def fake_db_write(content: str) -> None:
        writes_attempted.append(content)

    # Normal case
    clean, detected = scrubber.scrub_text("Call me at 415-555-0100")
    fake_db_write(clean)
    print(f"  Normal write: {clean!r}  (raw phone not stored)")

    # Simulate scrubber failure (patch the inner call)
    original_scrub = scrubber._inner.scrub_text

    def exploding_scrub(text: str):
        raise RuntimeError("simulated scrubber failure")

    scrubber._inner.scrub_text = exploding_scrub  # type: ignore[method-assign]

    try:
        clean2, _ = scrubber.scrub_text("some user data")
        fake_db_write(clean2)
    except RuntimeError as exc:
        print(f"  Scrubber failure caught: {exc}")
        print(f"  Writes attempted after failure: {len(writes_attempted)} (only the safe one)")

    scrubber._inner.scrub_text = original_scrub


if __name__ == "__main__":
    demo_text_scrubbing()
    demo_field_scrubbing()
    demo_pii_scrubber_class()
    demo_fail_closed()
    print("\nDone.")
