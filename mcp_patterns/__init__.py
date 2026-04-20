"""
mcp_patterns — Production-ready security patterns for MCP (Model Context Protocol) servers.

Quickstart::

    from mcp_patterns import scrub_pii, scrub_pii_field, PIIScrubber, FailClosedScrubber

    # Free-text scrubbing
    clean, found = scrub_pii("Email alice@example.com about the deal")
    # clean == "Email [REDACTED-EMAIL] about the deal"
    # found == ["email"]

    # Structured field scrubbing
    safe = scrub_pii_field("email", "alice@example.com")
    # safe == "a1b2c3d4"

    # Configurable scrubber with custom patterns
    import re
    scrubber = PIIScrubber(
        extra_patterns=[("emp_id", re.compile(r"EMP-\\d{6}"), "[REDACTED-EMP]")],
    )

    # Fail-closed policy enforcer
    safe_scrubber = FailClosedScrubber()
"""

from mcp_patterns.pii_scrubber import (
	FailClosedScrubber,
	PIIScrubber,
	scrub_pii,
	scrub_pii_field,
)

__all__ = [
	"scrub_pii",
	"scrub_pii_field",
	"PIIScrubber",
	"FailClosedScrubber",
]

__version__ = "0.1.0"
