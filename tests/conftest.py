"""
pytest fixtures for mcp_patterns tests.
"""
from __future__ import annotations

import re

import pytest

from mcp_patterns.pii_scrubber import PIIScrubber, FailClosedScrubber


@pytest.fixture()
def default_scrubber() -> PIIScrubber:
	"""PIIScrubber with no customisation."""
	return PIIScrubber()


@pytest.fixture()
def custom_scrubber() -> PIIScrubber:
	"""PIIScrubber with one domain-specific extra pattern."""
	return PIIScrubber(
		extra_patterns=[
			("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]"),
		],
		extra_drop_fields=frozenset({"internal_secret"}),
	)


@pytest.fixture()
def fail_closed() -> FailClosedScrubber:
	"""FailClosedScrubber wrapping the default PIIScrubber."""
	return FailClosedScrubber()


# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_email() -> str:
	return "alice@example.com"


@pytest.fixture()
def sample_pii_text(sample_email: str) -> str:
	return f"Please contact {sample_email} or call 415-555-0100 to discuss."


@pytest.fixture()
def sample_log_record() -> dict:
	return {
		"email": "bob@example.com",
		"token": "mnemo_token_1234567890abcd",
		"project_name": "Secret Project",
		"password": "super-secret",
		"description": "Reviewed the quarterly roadmap",
	}
