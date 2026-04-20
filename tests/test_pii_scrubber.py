"""
Tests for mcp_patterns.pii_scrubber.

Coverage:
  - scrub_pii: all built-in patterns, edge cases, extra_patterns
  - scrub_pii_field: DROP / HASH / TRUNCATE / OBFUSCATE / PASS-THROUGH
  - PIIScrubber: custom patterns, custom field sets, scrub_record
  - FailClosedScrubber: re-raises on scrubber failure
  - Regression tests to guard against regressions on known edge cases
"""
from __future__ import annotations

import hashlib
import re

import pytest

from mcp_patterns.pii_scrubber import (
	FailClosedScrubber,
	PIIScrubber,
	scrub_pii,
	scrub_pii_field,
)


# ===========================================================================
# scrub_pii — pattern-based (free-text)
# ===========================================================================


class TestScrubPiiEmail:
	def test_email_redacted(self):
		scrubbed, detected = scrub_pii("Contact alice@example.com for details.")
		assert "[REDACTED-EMAIL]" in scrubbed
		assert "alice@example.com" not in scrubbed
		assert "email" in detected

	def test_email_min_local_part(self):
		"""Two-char local part is the minimum accepted."""
		scrubbed, detected = scrub_pii("ab@example.com")
		assert "[REDACTED-EMAIL]" in scrubbed
		assert "email" in detected

	def test_single_char_local_part_not_matched(self):
		"""Single-char local part (e.g. 'a@b.com') should not match."""
		scrubbed, detected = scrub_pii("a@b.com is not a real email here")
		assert "email" not in detected

	def test_multiple_emails_all_redacted(self):
		# Both addresses have domain labels ≥2 chars; both must be redacted.
		scrubbed, detected = scrub_pii("cc alice@example.com and bob@corp.org")
		assert "alice@example.com" not in scrubbed
		assert "bob@corp.org" not in scrubbed
		assert "email" in detected

	def test_no_pii_unchanged(self):
		text = "This string has no sensitive data."
		scrubbed, detected = scrub_pii(text)
		assert scrubbed == text
		assert detected == []

	def test_empty_string(self):
		scrubbed, detected = scrub_pii("")
		assert scrubbed == ""
		assert detected == []


class TestScrubPiiCredentials:
	def test_aws_key_redacted(self):
		scrubbed, detected = scrub_pii("key=AKIAIOSFODNN7EXAMPLE123")
		assert "[REDACTED-API-KEY]" in scrubbed
		assert "aws_key" in detected

	def test_openai_key_redacted(self):
		key = "sk-" + "a" * 48
		scrubbed, detected = scrub_pii(f"Using {key} for inference")
		assert "[REDACTED-API-KEY]" in scrubbed
		assert "openai_key" in detected

	def test_jwt_redacted(self):
		# Craft a minimal valid JWT-like string (all segments ≥10 chars)
		jwt = "eyJhbGci." + "eyJzdWIi." + "SflKxwRJSMeKKF"  # short; should NOT match
		scrubbed, detected = scrub_pii(jwt)
		# This short JWT should NOT be flagged (segment lengths too short)
		assert "jwt" not in detected

	def test_jwt_long_segments_redacted(self):
		header = "eyJ" + "a" * 20
		payload = "eyJ" + "b" * 20
		sig = "c" * 20
		jwt = f"{header}.{payload}.{sig}"
		scrubbed, detected = scrub_pii(f"Token: {jwt}")
		assert "[REDACTED-JWT]" in scrubbed
		assert "jwt" in detected

	def test_password_assignment_redacted(self):
		scrubbed, detected = scrub_pii("password=hunter2 is set")
		assert "[REDACTED-PASSWORD]" in scrubbed
		assert "password" in detected

	def test_password_colon_syntax_redacted(self):
		scrubbed, detected = scrub_pii("password: mysecret")
		assert "[REDACTED-PASSWORD]" in scrubbed
		assert "password" in detected


class TestScrubPiiPII:
	def test_credit_card_redacted(self):
		scrubbed, detected = scrub_pii("Card: 4111 1111 1111 1111")
		assert "[REDACTED-CC]" in scrubbed
		assert "credit_card" in detected

	def test_ssn_redacted(self):
		scrubbed, detected = scrub_pii("SSN is 123-45-6789")
		assert "[REDACTED-SSN]" in scrubbed
		assert "ssn" in detected

	def test_phone_us_redacted(self):
		scrubbed, detected = scrub_pii("Call me at 415-555-0100")
		assert "[REDACTED-PHONE]" in scrubbed
		assert "phone" in detected

	def test_phone_international_redacted(self):
		scrubbed, detected = scrub_pii("Reach me at +1 415 555 0100")
		assert "[REDACTED-PHONE]" in scrubbed
		assert "phone" in detected


class TestScrubPiiOrdering:
	def test_detected_list_has_no_duplicates(self):
		"""Two emails in the text → 'email' appears only once in detected."""
		_, detected = scrub_pii("a@b.com and cc@dd.org are contacts")
		assert detected.count("email") == 1

	def test_api_key_before_password_no_collision(self):
		"""AWS key pattern runs before the generic password pattern."""
		text = "key AKIAIOSFODNN7EXAMPLE123 and password=secret"
		scrubbed, detected = scrub_pii(text)
		assert "aws_key" in detected
		assert "password" in detected


class TestScrubPiiExtraPatterns:
	def test_extra_pattern_applied(self):
		extra = [("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]")]
		scrubbed, detected = scrub_pii("Employee EMP-001234 contacted support.", extra_patterns=extra)
		assert "[REDACTED-EMP-ID]" in scrubbed
		assert "EMP-001234" not in scrubbed
		assert "emp_id" in detected

	def test_extra_pattern_does_not_affect_global_state(self):
		"""Calling with extra_patterns must not pollute subsequent calls."""
		extra = [("emp_id", re.compile(r"EMP-\d{6}"), "[REDACTED-EMP-ID]")]
		scrub_pii("EMP-001234", extra_patterns=extra)
		# Second call without extra_patterns must NOT redact the emp_id pattern
		scrubbed2, detected2 = scrub_pii("EMP-001234")
		assert "emp_id" not in detected2


# ===========================================================================
# scrub_pii_field — structured field-semantic scrubbing
# ===========================================================================


class TestScrubPiiFieldEmail:
	def test_email_hashed(self, sample_email):
		result = scrub_pii_field("email", sample_email)
		expected = hashlib.sha256(sample_email.encode()).hexdigest()[:8]
		assert result == expected

	def test_email_case_insensitive(self):
		lower = scrub_pii_field("email", "alice@example.com")
		upper = scrub_pii_field("email", "ALICE@EXAMPLE.COM")
		# Both normalize to lowercase before hashing
		assert lower == upper

	def test_email_deterministic(self, sample_email):
		assert scrub_pii_field("email", sample_email) == scrub_pii_field("email", sample_email)

	def test_email_address_alias(self):
		result = scrub_pii_field("email_address", "bob@corp.com")
		expected = hashlib.sha256("bob@corp.com".encode()).hexdigest()[:8]
		assert result == expected


class TestScrubPiiFieldToken:
	def test_token_truncated(self):
		token = "mnemo_token_abcd1234efgh5678"
		result = scrub_pii_field("token", token)
		assert result == f"...{token[-4:]}"

	def test_session_token(self):
		token = "sess_xxxxxxxxxxxxxxxxxABCD"
		assert scrub_pii_field("session_token", token) == f"...{token[-4:]}"

	def test_access_token(self):
		token = "at_longtoken1234"
		assert scrub_pii_field("access_token", token) == f"...{token[-4:]}"

	def test_refresh_token(self):
		token = "rt_longtoken5678"
		assert scrub_pii_field("refresh_token", token) == f"...{token[-4:]}"

	def test_jwt_field_truncated(self):
		token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		result = scrub_pii_field("jwt", token)
		assert result == f"...{token[-4:]}"

	def test_empty_token(self):
		assert scrub_pii_field("token", "") == "..."


class TestScrubPiiFieldDrop:
	@pytest.mark.parametrize("ft", ["password", "pwd", "pass", "api_key", "secret", "secret_key", "access_key"])
	def test_drop_fields(self, ft):
		assert scrub_pii_field(ft, "some-value") == ""

	def test_drop_case_insensitive(self):
		assert scrub_pii_field("PASSWORD", "value") == ""

	def test_drop_empty_input(self):
		assert scrub_pii_field("password", "") == ""


class TestScrubPiiFieldProject:
	def test_project_name_obfuscated(self):
		result = scrub_pii_field("project_name", "Q2 Roadmap")
		assert result.startswith("proj_")
		assert len(result) == 11  # "proj_" + 6 hex chars
		assert "Q2 Roadmap" not in result

	def test_project_name_deterministic(self):
		r1 = scrub_pii_field("project_name", "Alpha")
		r2 = scrub_pii_field("project_name", "Alpha")
		assert r1 == r2

	def test_different_projects_different_hashes(self):
		assert scrub_pii_field("project_name", "Alpha") != scrub_pii_field("project_name", "Beta")

	def test_project_alias(self):
		result = scrub_pii_field("project", "Internal Roadmap")
		assert result.startswith("proj_")


class TestScrubPiiFieldPassThrough:
	def test_unknown_field_unchanged(self):
		assert scrub_pii_field("description", "Reviewed the roadmap") == "Reviewed the roadmap"

	def test_decision_body_unchanged(self):
		body = "We will hire 10 engineers"
		assert scrub_pii_field("decision_body", body) == body

	def test_none_value_becomes_empty_string(self):
		assert scrub_pii_field("unknown_field", None) == ""

	def test_integer_value_coerced_to_string(self):
		assert scrub_pii_field("count", 42) == "42"


# ===========================================================================
# PIIScrubber class
# ===========================================================================


class TestPIIScrubberClass:
	def test_scrub_text_delegates_to_scrub_pii(self, default_scrubber):
		scrubbed, detected = default_scrubber.scrub_text("email alice@example.com")
		assert "[REDACTED-EMAIL]" in scrubbed
		assert "email" in detected

	def test_scrub_field_delegates_to_scrub_pii_field(self, default_scrubber):
		assert default_scrubber.scrub_field("password", "secret") == ""

	def test_custom_extra_pattern(self, custom_scrubber):
		scrubbed, detected = custom_scrubber.scrub_text("Employee EMP-001234 needs access")
		assert "[REDACTED-EMP-ID]" in scrubbed
		assert "emp_id" in detected

	def test_custom_drop_field(self, custom_scrubber):
		assert custom_scrubber.scrub_field("internal_secret", "top_secret_value") == ""

	def test_scrub_record_all_fields(self, sample_log_record):
		scrubber = PIIScrubber()
		result = scrubber.scrub_record(sample_log_record)

		assert result["email"] != "bob@example.com"
		assert result["token"].startswith("...")
		assert result["project_name"].startswith("proj_")
		assert result["password"] == ""
		assert result["description"] == "Reviewed the quarterly roadmap"

	def test_scrub_record_does_not_mutate_original(self, sample_log_record):
		original_copy = dict(sample_log_record)
		PIIScrubber().scrub_record(sample_log_record)
		assert sample_log_record == original_copy


# ===========================================================================
# FailClosedScrubber
# ===========================================================================


class TestFailClosedScrubber:
	def test_normal_scrubbing_passes_through(self, fail_closed):
		scrubbed, detected = fail_closed.scrub_text("email alice@example.com")
		assert "[REDACTED-EMAIL]" in scrubbed
		assert "email" in detected

	def test_scrubber_exception_propagates(self, fail_closed, monkeypatch):
		"""If the inner scrubber raises, FailClosedScrubber must re-raise (never swallow)."""
		def explode(text, extra_patterns=None):
			raise RuntimeError("scrubber exploded")

		monkeypatch.setattr("mcp_patterns.pii_scrubber.scrub_pii", explode)

		inner = PIIScrubber()
		fc = FailClosedScrubber(inner)

		with pytest.raises(RuntimeError, match="scrubber exploded"):
			fc.scrub_text("some text")

	def test_write_not_called_after_scrubber_failure(self, monkeypatch):
		"""Regression: simulates write-path — write must not be reached if scrubber fails."""
		writes_attempted = []

		def fake_write(content):
			writes_attempted.append(content)

		def exploding_scrub(text, extra_patterns=None):
			raise RuntimeError("simulated failure")

		monkeypatch.setattr("mcp_patterns.pii_scrubber.scrub_pii", exploding_scrub)
		fc = FailClosedScrubber()

		with pytest.raises(RuntimeError):
			clean, _ = fc.scrub_text("user data")
			fake_write(clean)  # must never reach here

		assert writes_attempted == [], "Write must not be called when scrubber fails"


# ===========================================================================
# Regression tests
# ===========================================================================


class TestRegressions:
	def test_regression_version_string_tld_not_matched_as_email(self):
		"""'node.1' or 'v2.0.3' must not trigger the email pattern."""
		text = "Using node.1 and version v2.0.3 in production"
		_, detected = scrub_pii(text)
		assert "email" not in detected

	def test_regression_single_char_local_not_email(self):
		"""'a@b.com' with 1-char local part must not match."""
		_, detected = scrub_pii("user a@b.com")
		assert "email" not in detected

	def test_regression_empty_text_returns_empty_list(self):
		scrubbed, detected = scrub_pii("")
		assert scrubbed == ""
		assert detected == []

	def test_regression_none_field_value_does_not_crash(self):
		"""None passed as value must not raise; returns empty string."""
		assert scrub_pii_field("password", None) == ""
		assert scrub_pii_field("unknown", None) == ""

	def test_regression_email_hash_is_8_hex_chars(self, sample_email):
		result = scrub_pii_field("email", sample_email)
		assert len(result) == 8
		assert all(c in "0123456789abcdef" for c in result)

	def test_regression_project_hash_is_11_chars(self):
		result = scrub_pii_field("project_name", "My Project")
		assert len(result) == 11
		assert result.startswith("proj_")
