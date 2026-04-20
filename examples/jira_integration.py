"""
examples/jira_integration.py — Example: PII-scrubbed Jira MCP server.

Demonstrates how to wire mcp_patterns into a Jira MCP tool handler so that
PII (emails, phone numbers, employee IDs, API keys) is scrubbed before being
written to your audit log or passed to the Jira API.

This example also shows how to register a custom domain-specific pattern
(Jira issue keys like PROJECT-1234) to obfuscate internal ticket references
in external-facing exports.

Run (requires no external dependencies beyond mcp_patterns):
    python examples/jira_integration.py
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from mcp_patterns import PIIScrubber, FailClosedScrubber, scrub_pii_field

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Custom scrubber: Jira-specific patterns
# ---------------------------------------------------------------------------
# Add a pattern that obfuscates internal Jira issue keys in external exports.
# This keeps the ticket *format* visible (for structure) but hides the project prefix.

_JIRA_SCRUBBER = PIIScrubber(
    extra_patterns=[
        # Matches PROJ-1234, ENG-9999, etc. — obfuscates the project prefix.
        (
            "jira_key",
            re.compile(r"\b([A-Z]{2,10})-(\d{1,6})\b"),
            "[REDACTED-ISSUE]",
        ),
    ],
    # Internal Jira API tokens treated as drop fields.
    extra_drop_fields=frozenset({"jira_api_token", "jira_pat"}),
)

_FAIL_CLOSED = FailClosedScrubber(inner=_JIRA_SCRUBBER)


# ---------------------------------------------------------------------------
# Stub: Jira API client
# ---------------------------------------------------------------------------

class JiraClient:
    """Minimal stub that prints instead of making real Jira API calls."""

    def create_issue(self, project: str, summary: str, description: str) -> dict[str, Any]:
        print(f"  [Jira] CREATE issue in {project}:")
        print(f"         summary: {summary!r}")
        print(f"         description: {description!r}")
        return {"id": "10042", "key": f"{project}-42", "self": "https://jira.example.com/rest/api/2/issue/10042"}

    def add_comment(self, issue_key: str, body: str) -> dict[str, Any]:
        print(f"  [Jira] COMMENT on {issue_key}: {body!r}")
        return {"id": "20001"}


_jira = JiraClient()
_AUDIT_LOG: list[dict[str, Any]] = []


def db_insert_audit(record: dict[str, Any]) -> None:
    _AUDIT_LOG.append(record)
    print(f"  [Audit] {json.dumps(record)}")


# ---------------------------------------------------------------------------
# MCP tool handler: create_jira_issue
# ---------------------------------------------------------------------------

def handle_create_jira_issue(arguments: dict[str, Any]) -> dict[str, Any]:
    """MCP tool handler: create a Jira issue.

    Scrubs PII from summary and description before creating the issue
    and before writing the audit log record.

    Arguments:
        project (str): Jira project key (e.g. "ENG")
        summary (str): Issue summary (may contain PII)
        description (str): Issue description (may contain PII)
        reporter_email (str): Reporter's email address
        api_token (str): Jira API token
    """
    project        = arguments.get("project", "ENG")
    summary        = arguments.get("summary", "")
    description    = arguments.get("description", "")
    reporter_email = arguments.get("reporter_email", "")
    api_token      = arguments.get("api_token", "")

    # Scrub summary and description before sending to Jira
    clean_summary, s_detected     = _FAIL_CLOSED.scrub_text(summary)
    clean_description, d_detected = _FAIL_CLOSED.scrub_text(description)

    all_detected = list(set(s_detected + d_detected))
    if all_detected:
        log.warning("PII detected in Jira issue creation", extra={"pii_types": all_detected, "project": project})

    # Create the issue with scrubbed content
    response = _jira.create_issue(
        project=project,
        summary=clean_summary,
        description=clean_description,
    )

    # Build scrubbed audit record
    audit = {
        "action":          "create_issue",
        "issue_key":       response.get("key"),
        "project":         project,
        "reporter_hash":   scrub_pii_field("email", reporter_email),
        "token_suffix":    scrub_pii_field("jira_api_token", api_token),  # custom drop field → ""
        "pii_detected":    all_detected,
    }
    db_insert_audit(audit)

    return {"issue_key": response.get("key"), "pii_scrubbed": all_detected}


# ---------------------------------------------------------------------------
# MCP tool handler: add_jira_comment
# ---------------------------------------------------------------------------

def handle_add_jira_comment(arguments: dict[str, Any]) -> dict[str, Any]:
    """MCP tool handler: add a comment to a Jira issue.

    Scrubs PII from the comment body before posting.

    Arguments:
        issue_key (str): Jira issue key (e.g. "ENG-42")
        body (str): Comment body (may contain PII)
        author_email (str): Commenter's email address
    """
    issue_key    = arguments.get("issue_key", "")
    body         = arguments.get("body", "")
    author_email = arguments.get("author_email", "")

    clean_body, detected = _FAIL_CLOSED.scrub_text(body)

    if detected:
        log.warning("PII in Jira comment", extra={"pii_types": detected, "issue": issue_key})

    response = _jira.add_comment(issue_key=issue_key, body=clean_body)

    audit = {
        "action":       "add_comment",
        "issue_key":    issue_key,
        "comment_id":   response.get("id"),
        "author_hash":  scrub_pii_field("email", author_email),
        "pii_detected": detected,
    }
    db_insert_audit(audit)

    return {"comment_id": response.get("id"), "pii_scrubbed": detected}


# ---------------------------------------------------------------------------
# MCP tool handler: export_issues (with full export-path scrubbing)
# ---------------------------------------------------------------------------

def handle_export_issues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Export Jira issues with PII and internal Jira keys scrubbed.

    In an external-facing export:
    - Free-text fields (summary, description) are scrubbed by pattern.
    - Internal Jira issue keys embedded in text are obfuscated.
    - Reporter emails are replaced with hashes.
    """
    exported = []
    for issue in issues:
        clean_summary, _ = _FAIL_CLOSED.scrub_text(issue.get("summary", ""))
        clean_desc, _    = _FAIL_CLOSED.scrub_text(issue.get("description", ""))
        exported.append({
            "key":         issue.get("key"),
            "summary":     clean_summary,
            "description": clean_desc,
            "reporter":    scrub_pii_field("email", issue.get("reporter_email", "")),
            "status":      issue.get("status"),
        })
    return exported


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Jira MCP Integration Example ===\n")

    print("1. Create issue with PII in summary and description:")
    result = handle_create_jira_issue({
        "project":        "ENG",
        "summary":        "Bug reported by alice@example.com — call 415-555-0100",
        "description":    "Customer alice@example.com (card: 4111 1111 1111 1111) filed this issue.",
        "reporter_email": "alice@example.com",
        "api_token":      "jira_pat_secret_1234567890abcdef",
    })
    print(f"   Result: {result}\n")

    print("2. Add comment with PII:")
    result = handle_add_jira_comment({
        "issue_key":    "ENG-42",
        "body":         "Assigned to bob@corp.com, SSN 123-45-6789 verified for identity check",
        "author_email": "carol@corp.com",
    })
    print(f"   Result: {result}\n")

    print("3. Export issues (external-facing, with Jira keys obfuscated):")
    issues = [
        {
            "key": "ENG-42",
            "summary": "Bug from alice@example.com re: ENG-40",
            "description": "See ENG-38 and ENG-39 for context. Contact alice@example.com.",
            "reporter_email": "alice@example.com",
            "status": "open",
        }
    ]
    exported = handle_export_issues(issues)
    print(f"   Exported: {json.dumps(exported, indent=2)}\n")

    print(f"Audit log ({len(_AUDIT_LOG)} entries):")
    for entry in _AUDIT_LOG:
        print(f"  {json.dumps(entry)}")
