# mcp-patterns

Production-ready patterns for MCP (Model Context Protocol) servers — from security to routing, latency, and agent design.

## The Field Report

[![Download PDF](https://img.shields.io/badge/Download%20Free%20PDF-MCP%20Is%20the%20Product-red?style=for-the-badge&logo=adobeacrobatreader)](https://github.com/ragsvasan/mcp-patterns/releases/download/v1.0/MCP-is-the-Product.pdf)

**[MCP Is the Product](https://github.com/ragsvasan/mcp-patterns/releases/download/v1.0/MCP-is-the-Product.pdf)** — A field report from twelve weeks of building a headless AI coaching app. What the spec doesn't tell you about routing, latency, security, and the language between intent and action. VitalSync is the case study. The lessons generalize.

> *"The spec is the handshake. The hard work is in the product."*

---

**Current pattern: PII Scrubber** — detect and redact sensitive data before it reaches persistent storage.

## Why this exists

MCP servers integrate with external tools (Slack, Jira, databases, analytics platforms) and log user input. Without standardized PII handling, each integration rebuilds scrubbing logic independently — and raw emails, API keys, or SSNs end up in audit trails.

This library provides a tested, extensible scrubber with a **fail-closed policy**: if scrubbing fails, the write is blocked. Unscrubbed data never reaches persistent storage.

## Installation

```bash
pip install mcp-patterns
```

## Quickstart

```python
from mcp_patterns import scrub_pii, scrub_pii_field, FailClosedScrubber

# Free-text scrubbing
scrubbed, detected = scrub_pii("Contact alice@example.com or call 415-555-0100")
# scrubbed  == "Contact [REDACTED-EMAIL] or call [REDACTED-PHONE]"
# detected  == ["email", "phone"]

# Structured field scrubbing
safe_email = scrub_pii_field("email", "alice@example.com")
# safe_email == "a1b2c3d4"  (SHA-256 first 8 hex chars — deterministic, joinable)

safe_token = scrub_pii_field("token", "sess_abcdefgh1234")
# safe_token == "...1234"

safe_pass  = scrub_pii_field("password", "hunter2")
# safe_pass  == ""  (dropped entirely)

# Fail-closed write path
scrubber = FailClosedScrubber()
clean, _ = scrubber.scrub_text(user_input)  # raises if scrubber fails
await db.insert(content=clean)              # never reached if scrubber raised
```

## Two-tier architecture

### Tier 1 — Pattern-based (free-text)

Regex registry for 8 built-in PII types, applied in specificity order:

| Pattern | Matches | Replacement |
|---|---|---|
| `aws_key` | `AKIA` + 16 chars | `[REDACTED-API-KEY]` |
| `openai_key` | `sk-` + 48 chars | `[REDACTED-API-KEY]` |
| `jwt` | Three base64url segments ≥10 chars | `[REDACTED-JWT]` |
| `password` | `password: value` / `password=value` | `[REDACTED-PASSWORD]` |
| `email` | Standard email (local ≥2 chars, TLD 2–6 alpha) | `[REDACTED-EMAIL]` |
| `credit_card` | 16-digit card number | `[REDACTED-CC]` |
| `ssn` | `NNN-NN-NNNN` | `[REDACTED-SSN]` |
| `phone` | US phone (with/without `+1` prefix) | `[REDACTED-PHONE]` |

### Tier 2 — Field-semantic (structured audit)

| Field class | Fields | Behaviour |
|---|---|---|
| DROP | `password`, `pwd`, `pass`, `api_key`, `secret`, `secret_key`, `access_key` | `""` |
| HASH | `email`, `email_address` | SHA-256(lower.strip())[:8] |
| TRUNCATE | `token`, `session_token`, `jwt`, `access_token`, `refresh_token` | `...{last4}` |
| OBFUSCATE | `project_name`, `project` | `proj_{sha256[:6]}` |
| PASS-THROUGH | everything else | unchanged |

## Custom patterns

```python
import re
from mcp_patterns import PIIScrubber

scrubber = PIIScrubber(
    extra_patterns=[
        ("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]"),
    ],
    extra_drop_fields=frozenset({"internal_api_secret"}),
    extra_email_fields=frozenset({"contact_email", "billing_email"}),
)

scrubbed, detected = scrubber.scrub_text("EMP-001234 called support")
safe_record = scrubber.scrub_record({"email": "alice@corp.com", "password": "s3cr3t"})
```

## Fail-closed policy

```python
from mcp_patterns import FailClosedScrubber

scrubber = FailClosedScrubber()

try:
    clean, detected = scrubber.scrub_text(user_input)
except Exception:
    # Scrubber failed — do NOT write. Return error to caller.
    raise

await db.insert(content=clean)
```

The `FailClosedScrubber` logs the exception at WARNING level and re-raises. It never silently allows unscrubbed data through.

## Deterministic hashing

Email addresses are SHA-256 hashed (first 8 hex chars, case-normalized). This means:
- Same email always produces the same hash across processes and restarts.
- Audit trail joins work: join on `email_hash` without storing raw emails.
- Case variants and whitespace are normalized before hashing.

```python
scrub_pii_field("email", "alice@example.com")  # → "a3f2b1c9"
scrub_pii_field("email", "ALICE@EXAMPLE.COM")  # → "a3f2b1c9"  (same)
scrub_pii_field("email", "  alice@example.com  ")  # → "a3f2b1c9"  (same)
```

## Zero runtime dependencies

`mcp-patterns` uses only Python stdlib: `re`, `hashlib`, `logging`, `dataclasses`. No install bloat.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

Coverage report:

```bash
pytest --cov=mcp_patterns --cov-report=term-missing
```

## Compliance

See [`docs/COMPLIANCE_CHECKLIST.md`](docs/COMPLIANCE_CHECKLIST.md) for SOC 2, GDPR, and HIPAA control mappings.

## Examples

- [`examples/basic_scrubbing.py`](examples/basic_scrubbing.py) — minimal demo of all APIs
- [`examples/slack_integration.py`](examples/slack_integration.py) — Slack MCP server with scrubbed writes
- [`examples/jira_integration.py`](examples/jira_integration.py) — Jira MCP server with custom patterns

## Documentation

- [`docs/PATTERN_GUIDE.md`](docs/PATTERN_GUIDE.md) — design rationale, pattern ordering, extensibility
- [`docs/INTEGRATION_GUIDE.md`](docs/INTEGRATION_GUIDE.md) — wiring patterns, testing checklist
- [`docs/COMPLIANCE_CHECKLIST.md`](docs/COMPLIANCE_CHECKLIST.md) — SOC 2 / GDPR / HIPAA checklist

## License

MIT
