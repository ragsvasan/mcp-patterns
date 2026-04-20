# MCP PII Scrubbing Pattern — Design Guide

## Problem

MCP-based applications integrate with dozens of third-party tools (Slack, Jira, Linear, custom business systems) to log decisions, capture sessions, and export audit data. Without standardized PII handling, each integration rebuilds filtering logic independently:

- Some scrub PII before write; others scrub only on export.
- Sensitive fields leak into middleware logs, observability systems, and search indexes.
- Compliance audits fail when raw SSNs or credit cards appear in audit trails.
- Testing is fragmented: one integration passes PII to a database, another to S3, a third to email.

**PII-awareness should be a platform concern, not an integration concern.**

---

## Solution: Two-Tier Scrubbing

### Tier 1 — Pattern-based scrubbing (free-text layer)

Detects PII in free-text fields (emails, phone numbers, credit cards, SSNs, API keys, JWTs). Runs before every write to persistent storage.

Patterns are ordered so that **specific patterns match before generic ones** — API key patterns run first to avoid partial matches on overlapping text.

Returns both scrubbed text and a list of detected PII types (useful for monitoring/alerting).

### Tier 2 — Field-semantic scrubbing (structured audit layer)

Tags database columns by sensitivity class and applies deterministic redaction per field type.

| Field class | Fields | Behaviour |
|---|---|---|
| DROP | `password`, `pwd`, `pass`, `api_key`, `secret`, `secret_key`, `access_key` | Returns `""` (dropped entirely) |
| HASH | `email`, `email_address` | SHA-256(lower.strip())[:8] — deterministic, joinable |
| TRUNCATE | `token`, `session_token`, `jwt`, `access_token`, `refresh_token` | `...{last4}` |
| OBFUSCATE | `project_name`, `project` | `proj_{sha256[:6]}` |
| PASS-THROUGH | everything else | Returned unchanged |

---

## How It Works

```python
from mcp_patterns import scrub_pii, scrub_pii_field

# Tier 1: free-text
content = "We will email alice@example.com about the contract"
scrubbed, detected = scrub_pii(content)
# scrubbed  = "We will email [REDACTED-EMAIL] about the contract"
# detected  = ["email"]

# Tier 2: structured fields
record = {
    "audit_email": "alice@example.com",
    "audit_session_token": "mnemo_1234567890abcdef",
    "audit_password_attempt": "secret123",
}

record["audit_email"]            = scrub_pii_field("email",    record["audit_email"])
# → "a1b2c3d4" (SHA-256 hash, 8 hex chars)

record["audit_session_token"]    = scrub_pii_field("token",    record["audit_session_token"])
# → "...cdef" (last 4 chars)

record["audit_password_attempt"] = scrub_pii_field("password", record["audit_password_attempt"])
# → "" (dropped)
```

---

## Built-in Pattern Registry

Patterns are evaluated in this order:

| Name | What it matches | Replacement |
|---|---|---|
| `aws_key` | `AKIA` + 16 alphanumeric chars | `[REDACTED-API-KEY]` |
| `openai_key` | `sk-` + 48 alphanumeric chars | `[REDACTED-API-KEY]` |
| `jwt` | Three base64url segments ≥10 chars each starting with `eyJ` | `[REDACTED-JWT]` |
| `password` | `password: value` or `password=value` (case-insensitive) | `[REDACTED-PASSWORD]` |
| `email` | Standard email address (local ≥2 chars, TLD 2–6 alpha) | `[REDACTED-EMAIL]` |
| `credit_card` | 16 digits optionally separated by spaces or hyphens | `[REDACTED-CC]` |
| `ssn` | `NNN-NN-NNNN` format | `[REDACTED-SSN]` |
| `phone` | US phone numbers including international prefix `+1` | `[REDACTED-PHONE]` |

### Why this ordering matters

If `password` ran before `aws_key`, a string like `password=AKIA...` would be partially consumed by the password pattern before the AWS key pattern could match. Specific patterns (AWS key, OpenAI key, JWT) run first.

---

## Extending the Pattern Registry

### Per-call extra patterns

```python
import re
from mcp_patterns import scrub_pii

extra = [
    ("employee_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]"),
    ("customer_ref", re.compile(r"CUST-[A-Z]{2}\d{8}"), "[REDACTED-CUST]"),
]

scrubbed, detected = scrub_pii(text, extra_patterns=extra)
```

Extra patterns run *before* the built-in registry and do not modify global state.

### Configurable scrubber class

```python
import re
from mcp_patterns import PIIScrubber

scrubber = PIIScrubber(
    extra_patterns=[
        ("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]"),
    ],
    extra_drop_fields=frozenset({"internal_api_secret"}),
    extra_email_fields=frozenset({"contact_email", "billing_email"}),
    extra_token_fields=frozenset({"oauth_token"}),
)

scrubbed, detected = scrubber.scrub_text("EMP-001234 called support")
safe = scrubber.scrub_field("billing_email", "alice@corp.com")
record = scrubber.scrub_record({"internal_api_secret": "...", "description": "..."})
```

---

## Fail-Closed Policy

If the scrubber raises an unexpected exception (e.g., regex catastrophic backtracking, OOM), the write **must be refused**. Unscrubbed data must never reach persistent storage.

Use `FailClosedScrubber` to enforce this automatically:

```python
from mcp_patterns import FailClosedScrubber

scrubber = FailClosedScrubber()

try:
    clean, detected = scrubber.scrub_text(user_input)
except Exception:
    # Do NOT fall through to the write. Return an error to the caller.
    raise

await db.insert(content=clean)
```

The `FailClosedScrubber` logs the exception and re-raises. It never silently swallows failures.

---

## Determinism and Audit Trail Joins

SHA-256 hashing of email addresses is deterministic: the same email always produces the same 8-char hex digest. This means you can:

- Join audit records by hashed email across sessions without storing the raw email.
- Verify that a specific email was involved in an event without exposing it.
- Provide auditors with consistent pseudonymous identifiers.

```python
scrub_pii_field("email", "alice@example.com")  # → "a3f2b1c9" (always the same)
scrub_pii_field("email", "ALICE@EXAMPLE.COM")  # → "a3f2b1c9" (case-normalized)
scrub_pii_field("email", "  alice@example.com  ")  # → "a3f2b1c9" (whitespace trimmed)
```

---

## Testing Checklist

- [ ] Scrubbed content persists; raw PII does not (write path test).
- [ ] Export ZIP/CSV files contain only redacted tokens.
- [ ] Scrubber exception blocks the write — add a test that patches `scrub_pii` to raise and asserts the DB write is never reached.
- [ ] Deterministic hashing: same email always hashes to same digest across test runs.
- [ ] Extra patterns do not pollute global state between test cases.
- [ ] `None` values do not crash `scrub_pii_field`.
- [ ] Single-char local part email addresses are NOT matched (false positive guard).
- [ ] Version strings like `v2.0.3` are NOT matched as emails.

---

## Performance Notes

Regex patterns are pre-compiled at module import time. For high-throughput workloads:

- Consider batching scrubbing calls rather than calling per-field in a tight loop.
- Monitor for catastrophic backtracking on adversarial input. The built-in patterns have bounded complexity, but custom patterns should be reviewed carefully.
- The pattern registry is evaluated linearly — O(P × N) where P = number of patterns and N = text length. For typical MCP log payloads (< 10 KB), this is negligible.
