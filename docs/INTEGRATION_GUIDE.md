# Integration Guide — Using mcp_patterns in Your MCP Server

This guide shows how to wire `mcp_patterns` into a Python MCP server so that PII is scrubbed before every write to persistent storage.

---

## Installation

```bash
pip install mcp-patterns
```

Or from source:

```bash
git clone https://github.com/your-org/mcp-patterns
cd mcp-patterns
pip install -e .
```

---

## Quickstart — Minimal Wiring

The three-line integration:

```python
from mcp_patterns import scrub_pii

# In your MCP tool handler, before any DB/API write:
raw_content = arguments["content"]
clean_content, detected = scrub_pii(raw_content)
# Use clean_content for storage; log detected for observability
```

---

## Pattern 1 — Pre-Write Middleware (recommended)

Wrap every tool handler's write path with a scrubbing call. The scrubber runs *after* parameter validation and *before* the database/API call.

```python
from mcp_patterns import FailClosedScrubber

_scrubber = FailClosedScrubber()


def handle_log_decision(arguments: dict) -> dict:
    # 1. Validate parameters
    content   = arguments.get("content", "")
    rationale = arguments.get("rationale", "")

    # 2. Scrub PII — fail-closed: raises if scrubber fails
    clean_content, _ = _scrubber.scrub_text(content)
    clean_rationale, _ = _scrubber.scrub_text(rationale)

    # 3. Write to persistent storage
    result = db.insert_decision(
        content=clean_content,
        rationale=clean_rationale,
    )
    return result
```

If `scrub_text` raises, the exception propagates and the write never happens.

---

## Pattern 2 — Structured Field Scrubbing for Audit Logs

Use `scrub_pii_field` when exporting or logging structured records:

```python
from mcp_patterns import scrub_pii_field


def build_audit_record(user_email: str, session_token: str, project: str) -> dict:
    return {
        "email_hash":    scrub_pii_field("email", user_email),
        "token_suffix":  scrub_pii_field("token", session_token),
        "project_label": scrub_pii_field("project_name", project),
    }
```

The returned record is safe to write to logs, export to CSV, or send to an observability platform.

---

## Pattern 3 — Record Scrubbing (bulk)

Use `PIIScrubber.scrub_record` when you have a flat dict of fields:

```python
from mcp_patterns import PIIScrubber

scrubber = PIIScrubber()

raw_record = {
    "email":        "alice@example.com",
    "password":     "secret",
    "session_token": "tok_1234567890abcd",
    "project_name": "Q2 Roadmap",
    "description":  "Reviewed the hiring plan",
}

safe_record = scrubber.scrub_record(raw_record)
# {
#   "email":         "a1b2c3d4",          # hashed
#   "password":      "",                   # dropped
#   "session_token": "...abcd",           # truncated
#   "project_name":  "proj_abc123",       # obfuscated
#   "description":   "Reviewed the hiring plan",  # unchanged
# }
```

---

## Pattern 4 — Export Path Scrubbing

When generating ZIP/CSV exports, scrub all text fields before serializing:

```python
from mcp_patterns import scrub_pii
import json, zipfile, io

TEXT_FIELDS = {
    "decisions": ["content", "rationale", "outcome_notes"],
    "sessions":  ["task", "output", "summary"],
}


def scrub_records(dataset_name: str, records: list) -> list:
    fields = TEXT_FIELDS.get(dataset_name, [])
    scrubbed = []
    for rec in records:
        row = dict(rec)
        for f in fields:
            if isinstance(row.get(f), str):
                row[f], _ = scrub_pii(row[f])
        scrubbed.append(row)
    return scrubbed


def export_to_zip(profile: str, datasets: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, records in datasets.items():
            safe = scrub_records(name, records)
            zf.writestr(f"{name}.json", json.dumps(safe, indent=2))
    return buf.getvalue()
```

---

## Pattern 5 — Custom Domain Patterns

Register domain-specific patterns without modifying library code:

```python
import re
from mcp_patterns import PIIScrubber

# Example: internal employee IDs, customer reference numbers
scrubber = PIIScrubber(
    extra_patterns=[
        ("emp_id",    re.compile(r"EMP-\d{6}"),          "[REDACTED-EMP-ID]"),
        ("cust_ref",  re.compile(r"CUST-[A-Z]{2}\d{8}"), "[REDACTED-CUST]"),
        ("ticket_id", re.compile(r"TKT-\d{8}"),          "[REDACTED-TKT]"),
    ],
    extra_drop_fields=frozenset({"internal_api_secret", "db_password"}),
)

scrubbed, detected = scrubber.scrub_text(
    "Employee EMP-001234 opened TKT-00012345 about CUST-AB12345678"
)
```

---

## Observability: Monitoring PII Detection

`scrub_pii` returns the list of detected PII types. Use this to:
- Alert on unexpected PII types in your data (e.g., SSNs or credit cards where you don't expect them).
- Track PII scrubbing rates in your metrics system.

```python
import logging
from mcp_patterns import scrub_pii

log = logging.getLogger(__name__)

clean, detected = scrub_pii(user_input)
if detected:
    log.warning("PII detected in tool input", extra={"pii_types": detected})
```

---

## Testing Your Integration

Write a test that verifies raw PII never reaches the write path:

```python
from unittest.mock import patch, MagicMock
from mcp_patterns import scrub_pii


def test_pii_never_reaches_database(monkeypatch):
    captured = []

    def fake_db_insert(content, **kwargs):
        captured.append(content)

    monkeypatch.setattr("myserver.db.insert_decision", fake_db_insert)

    handle_log_decision({"content": "Contact alice@example.com"})

    assert captured, "DB insert must be called"
    assert "alice@example.com" not in captured[0]
    assert "[REDACTED-EMAIL]" in captured[0]


def test_regression_scrubber_failure_blocks_write(monkeypatch):
    """Scrubber failure must block the DB write (fail-closed policy)."""
    writes = []
    monkeypatch.setattr("mcp_patterns.pii_scrubber.scrub_pii", lambda t, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr("myserver.db.insert_decision", lambda **k: writes.append(k))

    import pytest
    with pytest.raises(RuntimeError):
        handle_log_decision({"content": "some text"})

    assert writes == [], "Write must not be called when scrubber fails"
```

---

## Checklist

- [ ] `scrub_pii` called on all free-text fields before DB/API write.
- [ ] `scrub_pii_field` applied to all structured audit fields before export.
- [ ] `FailClosedScrubber` (or equivalent try/except) used on the write path.
- [ ] Scrubber exception tested: verify write is never reached.
- [ ] Custom domain patterns registered if your data contains non-standard PII formats.
- [ ] `detected` list monitored/logged for unexpected PII types.
