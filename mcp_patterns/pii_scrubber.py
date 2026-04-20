"""
mcp_patterns/pii_scrubber.py — Reusable PII detection and redaction for MCP servers.

Two-tier approach:
  1. Pattern-based scrubbing (free-text layer) — regex registry for emails,
     phones, credit cards, SSNs, API keys, JWTs.
  2. Field-semantic scrubbing (structured audit layer) — redaction policy per
     field type (DROP, HASH, TRUNCATE, PASS-THROUGH).

Usage::

    from mcp_patterns.pii_scrubber import scrub_pii, scrub_pii_field

    # Free-text scrubbing
    scrubbed, detected = scrub_pii("Contact alice@example.com about the deal")
    # scrubbed  == "Contact [REDACTED-EMAIL] about the deal"
    # detected  == ["email"]

    # Structured field scrubbing
    safe = scrub_pii_field("email", "alice@example.com")
    # safe == "a1b2c3d4"  (SHA-256 first 8 hex chars)

Fail-closed policy
------------------
If either function raises an unexpected exception, the caller is responsible
for refusing the downstream write. Unscrubbed data must never reach persistent
storage. See ``FailClosedScrubber`` for a convenience wrapper that enforces
this automatically.
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------

#: A single pattern registry entry.
PatternEntry = Tuple[str, re.Pattern[str], str]


# ---------------------------------------------------------------------------
# Default pattern registry
# ---------------------------------------------------------------------------
# Ordered so that specific patterns match before generic ones.
# API key patterns come first to prevent partial-match collisions with the
# generic ``password`` pattern.

_DEFAULT_PATTERNS: List[PatternEntry] = [
	# --- Credential patterns (most specific first) ---
	(
		"aws_key",
		re.compile(r"AKIA[0-9A-Z]{16}"),
		"[REDACTED-API-KEY]",
	),
	(
		"openai_key",
		re.compile(r"sk-[a-zA-Z0-9]{48}"),
		"[REDACTED-API-KEY]",
	),
	(
		"jwt",
		# Minimum segment lengths prevent false positives on short base64 strings.
		re.compile(
			r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
		),
		"[REDACTED-JWT]",
	),
	(
		"password",
		re.compile(r"(?i)password\s*[:=]\s*\S+"),
		"[REDACTED-PASSWORD]",
	),
	# --- PII patterns ---
	(
		"email",
		# Local part ≥2 chars; domain label ≥2 chars before TLD; TLD 2–6 alpha.
		# Rejects single-char local parts and version-string TLDs (e.g. ".1").
		re.compile(
			r"\b[A-Za-z0-9][A-Za-z0-9._%+-]+@[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"
		),
		"[REDACTED-EMAIL]",
	),
	(
		"credit_card",
		re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
		"[REDACTED-CC]",
	),
	(
		"ssn",
		re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
		"[REDACTED-SSN]",
	),
	(
		"phone",
		re.compile(
			r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
		),
		"[REDACTED-PHONE]",
	),
]


# ---------------------------------------------------------------------------
# Pattern-based scrubber
# ---------------------------------------------------------------------------


def scrub_pii(
	text: str,
	extra_patterns: Optional[List[PatternEntry]] = None,
) -> Tuple[str, List[str]]:
	"""Scan *text* for PII patterns, redact in place, return ``(scrubbed, detected)``.

	Parameters
	----------
	text:
		The raw input string to scan and scrub.
	extra_patterns:
		Additional ``(name, compiled_regex, replacement)`` tuples prepended to
		the built-in registry. Use this to register domain-specific patterns
		(e.g., internal customer ID format) without modifying global state.

	Returns
	-------
	scrubbed:
		A copy of *text* with all detected PII replaced by redaction tokens.
	detected:
		Unique pattern names found (e.g. ``["email", "phone"]``).
		Empty list when no PII is detected.

	Notes
	-----
	- Patterns run in registration order; API-key patterns run before generic
	  patterns to prevent partial-match collisions.
	- The original *text* is never modified (strings are immutable in Python).
	- If you pass ``extra_patterns``, they run *before* the built-in patterns.
	"""
	if not text:
		return text, []

	patterns: List[PatternEntry] = list(extra_patterns or []) + _DEFAULT_PATTERNS

	scrubbed = text
	detected: List[str] = []

	for name, pattern, replacement in patterns:
		new_text, n_subs = pattern.subn(replacement, scrubbed)
		if n_subs > 0 and name not in detected:
			detected.append(name)
		scrubbed = new_text

	return scrubbed, detected


# ---------------------------------------------------------------------------
# Field-semantic scrubber
# ---------------------------------------------------------------------------

#: Fields whose values must be dropped entirely (empty string returned).
_DROP_FIELDS: FrozenSet[str] = frozenset(
	{"password", "pwd", "pass", "api_key", "secret", "secret_key", "access_key"}
)

#: Fields whose values are replaced with a short SHA-256 hash (8 hex chars).
_EMAIL_FIELDS: FrozenSet[str] = frozenset({"email", "email_address"})

#: Fields whose values are truncated to their last 4 characters.
_TOKEN_FIELDS: FrozenSet[str] = frozenset(
	{"token", "session_token", "jwt", "access_token", "refresh_token"}
)

#: Fields whose values are replaced with a stable obfuscated identifier.
_PROJECT_FIELDS: FrozenSet[str] = frozenset({"project_name", "project"})


def scrub_pii_field(field_type: str, value: object) -> str:
	"""Return a safe representation of *value* based on the semantic *field_type*.

	Redaction policy by field class:

	============= ==========================================================
	Field class   Behaviour
	============= ==========================================================
	DROP          ``password``, ``pwd``, ``pass``, ``api_key``, ``secret``,
	              ``secret_key``, ``access_key`` → ``""`` (dropped)
	HASH          ``email``, ``email_address`` → SHA-256(lower.strip())[:8]
	TRUNCATE      ``token``, ``session_token``, ``jwt``, ``access_token``,
	              ``refresh_token`` → ``f"...{value[-4:]}"``
	OBFUSCATE     ``project_name``, ``project`` → ``f"proj_{sha256[:6]}"``
	PASS-THROUGH  anything else → value unchanged
	============= ==========================================================

	Parameters
	----------
	field_type:
		Semantic name of the field (case-insensitive).
	value:
		Field value. Non-string values are coerced to ``str``; ``None`` → ``""``.

	Returns
	-------
	str
		Safe representation of the value, never ``None``.
	"""
	ft = field_type.lower() if field_type else ""
	str_value: str = (
		value if isinstance(value, str) else (str(value) if value is not None else "")
	)

	if ft in _DROP_FIELDS:
		return ""

	if ft in _EMAIL_FIELDS:
		normalized = str_value.strip().lower()
		return hashlib.sha256(normalized.encode()).hexdigest()[:8]

	if ft in _TOKEN_FIELDS:
		if len(str_value) == 0:
			return "..."
		return f"...{str_value[-4:]}"

	if ft in _PROJECT_FIELDS:
		return f"proj_{hashlib.sha256(str_value.encode()).hexdigest()[:6]}"

	return str_value


# ---------------------------------------------------------------------------
# Extensible scrubber class
# ---------------------------------------------------------------------------


@dataclass
class PIIScrubber:
	"""Configurable scrubber that wraps ``scrub_pii`` and ``scrub_pii_field``.

	Use this when you need to:
	- Register domain-specific patterns at construction time.
	- Extend field classification sets without monkey-patching module globals.
	- Carry scrubber configuration through dependency injection.

	Example::

		scrubber = PIIScrubber(
		    extra_patterns=[
		        ("employee_id", re.compile(r"EMP-\\d{6}"), "[REDACTED-EMP-ID]"),
		    ],
		    extra_drop_fields={"internal_secret"},
		    extra_email_fields={"contact_email"},
		)
		scrubbed, detected = scrubber.scrub_text("Contact EMP-001234 or alice@corp.com")
		safe = scrubber.scrub_field("contact_email", "alice@corp.com")
	"""

	extra_patterns: List[PatternEntry] = field(default_factory=list)
	extra_drop_fields: FrozenSet[str] = field(default_factory=frozenset)
	extra_email_fields: FrozenSet[str] = field(default_factory=frozenset)
	extra_token_fields: FrozenSet[str] = field(default_factory=frozenset)
	extra_project_fields: FrozenSet[str] = field(default_factory=frozenset)

	def scrub_text(self, text: str) -> Tuple[str, List[str]]:
		"""Apply pattern-based scrubbing to free-form *text*.

		Returns ``(scrubbed_text, detected_pattern_names)``.
		"""
		return scrub_pii(text, extra_patterns=self.extra_patterns)

	def scrub_field(self, field_type: str, value: object) -> str:
		"""Apply field-semantic scrubbing based on *field_type*.

		Checks custom field sets first, then falls through to built-ins.
		"""
		ft = field_type.lower() if field_type else ""
		str_value: str = (
			value
			if isinstance(value, str)
			else (str(value) if value is not None else "")
		)

		if ft in self.extra_drop_fields:
			return ""
		if ft in self.extra_email_fields:
			normalized = str_value.strip().lower()
			return hashlib.sha256(normalized.encode()).hexdigest()[:8]
		if ft in self.extra_token_fields:
			return f"...{str_value[-4:]}" if str_value else "..."
		if ft in self.extra_project_fields:
			return f"proj_{hashlib.sha256(str_value.encode()).hexdigest()[:6]}"

		return scrub_pii_field(field_type, value)

	def scrub_record(self, record: Dict[str, object]) -> Dict[str, object]:
		"""Scrub all values in a flat dictionary using field-semantic rules.

		Keys are used as ``field_type`` for each value. Nested dicts/lists are
		not traversed — call ``scrub_text`` explicitly for nested free-text.

		Returns a new dict; *record* is never mutated.
		"""
		return {k: self.scrub_field(k, v) for k, v in record.items()}


# ---------------------------------------------------------------------------
# Fail-closed convenience wrapper
# ---------------------------------------------------------------------------


class FailClosedScrubber:
	"""Wraps a ``PIIScrubber`` and enforces the fail-closed write policy.

	If scrubbing raises any exception, ``scrub_text`` re-raises it so that the
	caller's write path is interrupted. Unscrubbed data must never reach
	persistent storage.

	Example::

		scrubber = FailClosedScrubber()

		try:
		    clean, detected = scrubber.scrub_text(user_input)
		except Exception:
		    # Do NOT proceed with the write.
		    raise

		await db.insert(content=clean)
	"""

	def __init__(self, inner: Optional[PIIScrubber] = None) -> None:
		self._inner = inner or PIIScrubber()

	def scrub_text(self, text: str) -> Tuple[str, List[str]]:
		"""Scrub *text*; re-raises any exception (never silently allows unsafe fallback)."""
		try:
			return self._inner.scrub_text(text)
		except Exception:
			logger.exception("PII scrubber failed; refusing write (fail-closed policy)")
			raise

	def scrub_field(self, field_type: str, value: object) -> str:
		"""Scrub a single structured field; re-raises on error."""
		try:
			return self._inner.scrub_field(field_type, value)
		except Exception:
			logger.exception("PII field scrubber failed; refusing write (fail-closed policy)")
			raise
