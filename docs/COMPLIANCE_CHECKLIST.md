# Compliance Checklist — SOC 2 / GDPR / HIPAA

Use this checklist to verify that your MCP server's PII scrubbing implementation satisfies the requirements of common compliance frameworks. Each item maps the `mcp_patterns` capability to a specific control.

---

## SOC 2 Type II

### CC6 — Logical and Physical Access Controls

| Control | Requirement | How mcp_patterns satisfies it |
|---|---|---|
| CC6.1 | Sensitive data classified before storage | `scrub_pii_field` enforces DROP/HASH/TRUNCATE per field class |
| CC6.7 | Transmission of sensitive data restricted | Scrubbing applied before API/DB write; raw PII never leaves the handler |
| CC6.6 | Logical access to sensitive data restricted | Hashed emails enable audit joins without exposing raw PII |

### CC7 — System Operations

| Control | Requirement | How mcp_patterns satisfies it |
|---|---|---|
| CC7.2 | Anomalies and incidents detected | `scrub_pii` returns `detected` list; wire to alerting on unexpected PII types |
| CC7.4 | Security incidents evaluated | Scrubber failure blocks write (fail-closed); logged at WARNING level |

### Checklist items

- [ ] `scrub_pii` wired into all MCP tool handlers before write.
- [ ] `detected` list forwarded to your monitoring/alerting system.
- [ ] Scrubber failure response tested and documented in your incident runbook.
- [ ] Audit log exports use `scrub_pii` on all free-text fields before serialization.
- [ ] Deterministic email hashing used for audit trail joins (no raw emails in logs).

---

## GDPR

### Article 5 — Principles

| Principle | Requirement | How mcp_patterns satisfies it |
|---|---|---|
| 5(1)(b) — Purpose limitation | Data used only for stated purpose | DROP policy prevents credential storage; HASH policy enables analytics without raw data |
| 5(1)(c) — Data minimisation | Collect only what is necessary | Passwords and API keys dropped entirely at write time |
| 5(1)(e) — Storage limitation | Not stored longer than necessary | Hashed values enable retention policy enforcement without raw PII |
| 5(1)(f) — Integrity and confidentiality | Appropriate security of personal data | PII never persists in plaintext; fail-closed policy prevents unscrubbed writes |

### Article 25 — Data Protection by Design

- [ ] PII scrubbing is the default, not opt-in: every write path applies scrubbing before storage.
- [ ] No fallback path that allows raw PII through if scrubbing fails.
- [ ] Custom patterns registered for any domain-specific PII formats in your data.

### Article 32 — Security of Processing

- [ ] Pseudonymisation applied: emails replaced with deterministic hashes.
- [ ] Appropriate technical measures: fail-closed scrubber prevents unredacted storage.
- [ ] Regular testing: regression test suite verifies scrubber coverage.

### Checklist items

- [ ] All MCP tool handlers scrub PII before write.
- [ ] Export path scrubs PII before generating ZIP/CSV/JSON files.
- [ ] No raw email addresses appear in audit logs, middleware logs, or observability platforms.
- [ ] Scrubber failure is logged and generates an alert (not silently ignored).
- [ ] Data subject access requests can be fulfilled using hashed email as a consistent pseudonymous key.

---

## HIPAA

### § 164.312 — Technical Safeguards

| Safeguard | Requirement | How mcp_patterns satisfies it |
|---|---|---|
| (a)(2)(iv) — Encryption and decryption | PHI must be protected | Scrubbing removes PHI from write path; no raw PHI stored in logs |
| (b) — Audit controls | Hardware, software, and procedural mechanisms to record activity | `detected` list enables audit trail of PII events |
| (c) — Integrity | PHI not improperly altered or destroyed | Fail-closed policy ensures scrubbed-only data persists |

### Safe Harbour De-identification (§ 164.514(b))

The built-in HASH policy for emails and OBFUSCATE policy for project names align with the Safe Harbour method, which requires removal or generalization of 18 PHI identifiers. Verify these specific identifiers are covered by your scrubbing configuration:

| PHI Identifier | Default coverage |
|---|---|
| Names | Not auto-detected (add domain-specific pattern if needed) |
| Geographic data | Not auto-detected (add if needed) |
| Dates (except year) | Not auto-detected |
| Phone numbers | Covered by `phone` pattern |
| Fax numbers | Not auto-detected |
| Email addresses | Covered by `email` pattern |
| SSN | Covered by `ssn` pattern |
| Medical record numbers | Not auto-detected (add domain-specific pattern) |
| Health plan beneficiary numbers | Not auto-detected |
| Account numbers | `credit_card` pattern covers 16-digit cards |
| Certificate/license numbers | Not auto-detected |
| Vehicle identifiers | Not auto-detected |
| Device identifiers | Not auto-detected |
| URLs | Not auto-detected |
| IP addresses | Not auto-detected (add if needed) |
| Biometric identifiers | Not auto-detected |
| Full-face photographs | N/A (text scrubber) |
| Any other unique identifier | Add domain-specific patterns |

### Checklist items

- [ ] All 18 PHI identifiers reviewed; custom patterns added for any not covered by defaults.
- [ ] Scrubber applied before any PHI reaches persistent storage.
- [ ] Audit log of `detected` types retained for HIPAA audit purposes.
- [ ] Fail-closed policy documented in your HIPAA security risk analysis.
- [ ] Business Associate Agreement (BAA) in place if using cloud services to store the hashed data.

---

## General Checklist (all frameworks)

### Implementation

- [ ] `scrub_pii` called on all free-text MCP tool inputs before write.
- [ ] `scrub_pii_field` applied to all structured audit fields before export.
- [ ] `FailClosedScrubber` (or equivalent) used on every write path.
- [ ] Scrubber exception tested: write is never reached when scrubber fails.
- [ ] Custom domain patterns registered for any non-standard PII formats.
- [ ] `detected` list wired to monitoring/alerting.

### Testing

- [ ] Regression test suite covers all built-in pattern types.
- [ ] Test verifies raw PII never reaches the DB write (not just that it's scrubbed in isolation).
- [ ] Test verifies scrubber failure blocks the write.
- [ ] Deterministic hashing tested: same email always produces same digest.
- [ ] False positive guards tested: version strings, short local parts not matched as emails.

### Documentation

- [ ] Redaction policy documented (what gets dropped vs. hashed vs. truncated, and why).
- [ ] Custom patterns documented and justified.
- [ ] Compliance mappings reviewed by your legal/compliance team.
- [ ] Incident runbook includes scrubber failure response.

### Operations

- [ ] Monitoring alert on unexpected PII types in production traffic.
- [ ] Regular (quarterly) review of pattern coverage against new data formats.
- [ ] Dependency updates tracked (new Python versions, regex engine changes).
