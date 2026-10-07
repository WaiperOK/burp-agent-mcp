"""Очистка данных перед тем, как они попадут в модель или в аудит-лог."""

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

# ПДн по именам полей JSON: значения заменяются целиком. Телефоны и номера в свободном тексте
# не ищем: шаблоны дают много ложных срабатываний (ID, timestamp), поэтому маскируем по ключам.
PHI_KEYS = (
    "firstName", "lastName", "middleName", "patronymic", "fullName",
    "birthDate", "dateOfBirth", "birthday", "phone", "phoneNumber", "mobile", "address",
    "passport", "passportNumber", "rnokpp", "ipn", "taxId", "iban", "cardNumber", "pesel",
)
_PHI_KEY_RE = re.compile(r'("(?:' + "|".join(PHI_KEYS) + r')"\s*:\s*)"(?:[^"\\]|\\.)*"', re.IGNORECASE)


def redact_text(text: str) -> str:
    """Скрывает чувствительные заголовки, типовые секреты и ПДн по ключам JSON."""
    text = _HEADER_RE.sub(lambda m: m.group(1) + ": [REDACTED]", text)
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _PHI_KEY_RE.sub(lambda m: m.group(1) + '"[PHI]"', text)


def truncate(text: str, limit: int) -> tuple[str, bool]:
    """Режет текст до limit символов, возвращает (текст, был_ли_обрезан)."""
    if len(text) <= limit:
        return text, False
    return text[:limit], True
