"""
examples/slack_integration.py — Example: PII-scrubbed Slack MCP server.

Demonstrates how to wire mcp_patterns into a Slack MCP tool handler so that
no PII (emails, phone numbers, API keys) reaches the Slack API or your audit
log before scrubbing.

This is a self-contained example. Replace the stub implementations with your
real Slack client and database calls.

Run (requires no external dependencies beyond mcp_patterns):
    python examples/slack_integration.py
"""
from __future__ import annotations

import json
import logging
from typing import Any

from mcp_patterns import FailClosedScrubber, scrub_pii_field

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared scrubber — one instance per process, reused across all handlers.
# FailClosedScrubber ensures a scrubber failure blocks the write.
# ---------------------------------------------------------------------------
_SCRUBBER = FailClosedScrubber()


# ---------------------------------------------------------------------------
# Stub: Slack API client
# ---------------------------------------------------------------------------

class SlackClient:
    """Minimal stub that prints instead of making real Slack API calls."""

    def post_message(self, channel: str, text: str) -> dict[str, Any]:
        print(f"  [Slack] POST to #{channel}: {text!r}")
        return {"ok": True, "ts": "1234567890.123456"}

    def log_audit_event(self, event: dict[str, Any]) -> None:
        print(f"  [Audit] {json.dumps(event)}")


_slack = SlackClient()


# ---------------------------------------------------------------------------
# Stub: Database
# ---------------------------------------------------------------------------

_DB: list[dict[str, Any]] = []


def db_insert_message_log(record: dict[str, Any]) -> None:
    _DB.append(record)
    print(f"  [DB] Inserted: {json.dumps(record)}")


# ---------------------------------------------------------------------------
# MCP tool handler: post_slack_message
# ---------------------------------------------------------------------------

def handle_post_slack_message(arguments: dict[str, Any]) -> dict[str, Any]:
    """MCP tool handler: post a message to a Slack channel.

    PII scrubbing applied at two levels:
      1. Free-text scrubbing on the message body before posting.
      2. Field-semantic scrubbing on the audit log record before DB insert.

    Arguments:
        channel (str): Slack channel name (e.g. "#general")
        message (str): Message text (may contain PII — scrubbed before send)
        sender_email (str): Sender's email address (stored as hash only)
        auth_token (str): Slack bot token (stored as truncated suffix only)
    """
    channel      = arguments.get("channel", "#general")
    message      = arguments.get("message", "")
    sender_email = arguments.get("sender_email", "")
    auth_token   = arguments.get("auth_token", "")

    # --- Tier 1: Scrub free-text message before sending to Slack ---
    clean_message, detected = _SCRUBBER.scrub_text(message)

    if detected:
        log.warning(
            "PII detected in Slack message before send",
            extra={"pii_types": detected, "channel": channel},
        )

    # --- Post scrubbed message to Slack ---
    response = _slack.post_message(channel=channel, text=clean_message)

    # --- Tier 2: Build scrubbed audit record before DB insert ---
    audit_record = {
        "channel":      channel,
        "message_ts":   response.get("ts"),
        # Raw email → SHA-256 hash (8 hex chars). Enables audit joins.
        "sender_hash":  scrub_pii_field("email", sender_email),
        # Raw token → last 4 chars. Never store full token.
        "token_suffix": scrub_pii_field("token", auth_token),
        "pii_detected": detected,
    }
    db_insert_message_log(audit_record)

    return {"ok": True, "message_ts": response.get("ts"), "pii_scrubbed": detected}


# ---------------------------------------------------------------------------
# MCP tool handler: search_slack_messages
# ---------------------------------------------------------------------------

def handle_search_slack_messages(arguments: dict[str, Any]) -> dict[str, Any]:
    """MCP tool handler: search Slack messages by keyword.

    The query itself is scrubbed before being logged (users sometimes
    paste PII into search boxes). Results are returned as-is — scrubbing
    on display is the caller's responsibility.
    """
    query        = arguments.get("query", "")
    sender_email = arguments.get("sender_email", "")

    # Scrub query before logging the search event
    clean_query, detected = _SCRUBBER.scrub_text(query)

    if detected:
        log.warning("PII in search query", extra={"pii_types": detected})

    # Log the search event with scrubbed fields
    search_log = {
        "action":       "search",
        "query_scrubbed": clean_query,
        "sender_hash":  scrub_pii_field("email", sender_email),
        "pii_detected": detected,
    }
    db_insert_message_log(search_log)

    # Stub: return dummy results
    return {
        "matches": [
            {"ts": "1234567890.000001", "text": "Quarterly review scheduled"},
        ],
        "query_pii_scrubbed": bool(detected),
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Slack MCP Integration Example ===\n")

    print("1. Posting message with PII in body:")
    result = handle_post_slack_message({
        "channel":      "#general",
        "message":      "Please contact alice@example.com or call 415-555-0100",
        "sender_email": "bob@company.com",
        "auth_token":   "xoxb-12345-67890-abcdefghijklmnop",
    })
    print(f"   Result: {result}\n")

    print("2. Posting clean message:")
    result = handle_post_slack_message({
        "channel":      "#eng",
        "message":      "Deployment to production successful",
        "sender_email": "ci-bot@company.com",
        "auth_token":   "xoxb-12345-67890-abcdefghijklmnop",
    })
    print(f"   Result: {result}\n")

    print("3. Search with PII in query:")
    result = handle_search_slack_messages({
        "query":        "contact alice@example.com about the deal",
        "sender_email": "carol@company.com",
    })
    print(f"   Result: {result}\n")

    print(f"DB records stored ({len(_DB)} total):")
    for rec in _DB:
        print(f"  {json.dumps(rec)}")
