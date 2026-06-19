"""Secret/risk helper functions extracted from mobile static scan helpers."""

from __future__ import annotations

import re
from pathlib import Path


def is_probable_version_ip(constants, ip_text: str, searchable_text: str, match_start: int) -> bool:
    try:
        parts = [int(part) for part in ip_text.split(".")]
    except ValueError:
        return False

    if len(parts) != 4:
        return False

    if ip_text in constants.KNOWN_PUBLIC_SERVICE_IPS:
        return False
    if parts[0] == 0:
        return True

    lowered = searchable_text.lower()
    ip_lower = ip_text.lower()
    snippet = constants._snippet_at_index(lowered, match_start, radius=60)
    if any(hint in snippet for hint in constants.OID_CONTEXT_HINTS):
        return True
    if any(hint in snippet for hint in constants.VERSION_CONTEXT_HINTS):
        return True
    if any(hint in snippet for hint in constants.NETWORK_CONTEXT_HINTS):
        return False

    match_end = match_start + len(ip_text)
    if match_end < len(lowered):
        trailing = lowered[match_end]
        if trailing in {"-", "_"} or trailing.isalnum():
            return True

    if all(part < 10 for part in parts) and ip_text not in constants.KNOWN_PUBLIC_SERVICE_IPS:
        return True
    if all(part <= 20 for part in parts):
        return True
    return bool(re.search(rf"{re.escape(ip_lower)}[a-z]", snippet))


def is_valuable_secret_evidence(constants, title: str, evidence: str) -> bool:
    text = evidence.strip()
    if len(text) < 10:
        return False

    if title in {"AWS Access Key", "Google API Key", "Stripe Live Key", "GitHub Token"}:
        return True

    if title == "JWT Token":
        return bool(
            re.search(
                r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
                text,
            )
        )

    if title == "Bearer/Auth Header Token":
        token_match = re.search(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)", text)
        if not token_match:
            return False
        token = token_match.group(1)
        return len(token) >= 20 and constants._entropy(token) >= 3.2

    value_match = constants.SECRET_VALUE_RE.search(text)
    if not value_match:
        return False
    value = value_match.group(1).strip()
    low_val = value.lower()
    if low_val in constants.NOISE_SECRET_VALUES:
        return False
    if value.startswith(("@string/", "@xml/", "BuildConfig.", "${", "#{")):
        return False
    if re.fullmatch(r"[0-9a-f]{6,}", low_val):
        return False
    if len(value) < 8:
        return False
    if constants._entropy(value) < 2.8 and not re.search(r"[A-Za-z].*[0-9]|[0-9].*[A-Za-z]", value):
        return False
    return True


def extract_printable_strings(constants, data: bytes, max_strings: int) -> list[str]:
    strings: list[str] = []
    for idx, match in enumerate(constants.PRINTABLE_RE.finditer(data)):
        if idx >= max_strings:
            break
        token = match.group().decode("utf-8", errors="ignore").strip()
        if token:
            strings.append(token)
    return strings


def read_text_if_possible(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def snippet_around(text: str, needle: str, radius: int = 80) -> str:
    index = text.find(needle)
    if index < 0:
        return needle
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return " ".join(text[start:end].split())


def normalize_line_no_truncate(text: str) -> str:
    return " ".join(str(text).strip().split())
