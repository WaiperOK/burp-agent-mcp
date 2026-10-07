"""Sanitising data before it reaches the model or the audit log."""

import re

SENSITIVE_HEADERS = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
)

_HEADER_RE = re.compile(
    r"^(" + "|".join(re.escape(h) for h in SENSITIVE_HEADERS) + r")[ \t]*:.*$",
    re.IGNORECASE | re.MULTILINE,
)

_PATTERNS = (
    (re.compile(r"eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), "[JWT]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[AWS_KEY]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [TOKEN]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
)

# Personal data by JSON field names: values are replaced entirely. Phone numbers and IDs in free text
# are not searched for: such patterns give many false positives (IDs, timestamps), so we mask by key.
PHI_KEYS = (
    "firstName", "lastName", "middleName", "patronymic", "fullName",
    "birthDate", "dateOfBirth", "birthday", "phone", "phoneNumber", "mobile", "address",
    "passport", "passportNumber", "rnokpp", "ipn", "taxId", "iban", "cardNumber", "pesel",
)
_PHI_KEY_RE = re.compile(r'("(?:' + "|".join(PHI_KEYS) + r')"\s*:\s*)"(?:[^"\\]|\\.)*"', re.IGNORECASE)


def redact_text(text: str) -> str:
    """Hides sensitive headers, common secrets and personal data by JSON key."""
    text = _HEADER_RE.sub(lambda m: m.group(1) + ": [REDACTED]", text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _PHI_KEY_RE.sub(lambda m: m.group(1) + '"[PHI]"', text)


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Cuts text to limit characters; returns (text, whether it was cut)."""
    if len(text) <= limit:
        return text, False
    return text[:limit], True
