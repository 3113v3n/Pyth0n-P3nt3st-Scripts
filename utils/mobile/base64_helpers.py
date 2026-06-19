"""Base64/payload helper functions extracted from mobile static scan helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
import xml.etree.ElementTree as ET


def beautify_decoded_payload(payload: str) -> tuple[str, str]:
    text = str(payload)
    stripped = text.strip()
    if not stripped:
        return text, "text"

    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, (dict, list)):
            return json.dumps(parsed, indent=2, ensure_ascii=False), "json"
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    if stripped.startswith("<") and stripped.endswith(">"):
        try:
            root = ET.fromstring(stripped)
            tree = ET.ElementTree(root)
            if hasattr(ET, "indent"):
                ET.indent(tree, space="  ")
            return ET.tostring(root, encoding="unicode"), "xml"
        except ET.ParseError:
            pass

    return text, "text"


def is_noise_base64_context(constants, context_window: str) -> bool:
    context = str(context_window or "")
    return bool(constants.BASE64_DATA_URI_PREFIX_RE.search(context))


def decode_base64_if_interesting(
    constants,
    token: str,
    *,
    context_window: str = "",
) -> tuple[str, str] | None:
    if len(token) < 24:
        return None
    if len(set(token)) < 8:
        return None
    if is_noise_base64_context(constants, context_window):
        return None

    def decode_once(candidate: str) -> str | None:
        normalized = re.sub(r"\s+", "", candidate)
        if len(normalized) < 8:
            return None
        try:
            padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
        except (ValueError, binascii.Error):
            return None
        if len(decoded_bytes) < 4 or len(decoded_bytes) > constants.MAX_BASE64_DECODE_BYTES:
            return None
        decoded_text_ = decoded_bytes.decode("utf-8", errors="ignore")
        if len(decoded_text_.strip()) < 4:
            return None
        if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in decoded_text_):
            return None
        return decoded_text_

    decoded_text = decode_once(token)
    if not decoded_text:
        return None

    for _ in range(constants.BASE64_MAX_DECODE_DEPTH - 1):
        candidate = re.sub(r"\s+", "", decoded_text)
        if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate or ""):
            break
        next_decoded = decode_once(candidate)
        if not next_decoded or next_decoded == decoded_text:
            break
        decoded_text = next_decoded

    analysis_text = decoded_text.strip()
    printable_ratio = sum(ch.isprintable() for ch in analysis_text) / max(len(analysis_text), 1)
    if printable_ratio < 0.9:
        return None
    ascii_ratio = sum(ord(ch) < 128 for ch in analysis_text) / max(len(analysis_text), 1)
    if ascii_ratio < 0.85:
        return None
    if not re.search(r"[A-Za-z]{4,}", analysis_text):
        return None
    if constants._entropy(analysis_text) < 2.6:
        return None

    lowered = analysis_text.lower()
    formatted_text, text_format = beautify_decoded_payload(analysis_text)

    sensitive_markers = (
        "http://",
        "https://",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "authorization",
        "bearer",
        "client_secret",
        "password",
        "private_key",
        "-----begin",
        "firebase",
        "googleapis",
        "jwt",
    )
    has_sensitive_marker = any(marker in lowered for marker in sensitive_markers)

    if not has_sensitive_marker:
        if "<svg" in lowered or "http://www.w3.org/2000/svg" in lowered:
            return None
        if lowered.startswith("<?xml") and "<svg" in lowered:
            return None
        if any(tag in lowered for tag in ("<path", "<rect", "<circle", "<polygon")) and "<svg" in lowered:
            return None

    if len(analysis_text) > 20_000 and not has_sensitive_marker:
        return None

    if has_sensitive_marker:
        return formatted_text, text_format

    try:
        parsed = json.loads(analysis_text)
        if isinstance(parsed, dict):
            keys = {str(k).lower() for k in parsed.keys()}
            interesting_keys = {
                "token", "access_token", "refresh_token", "secret", "api_key",
                "apikey", "password", "client_secret", "private_key",
            }
            if keys & interesting_keys:
                return formatted_text, text_format
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    return None


def build_base64_entry(rel_file: str, encoded_token: str, decoded_text: str, decoded_format: str) -> dict:
    return {
        "file": rel_file,
        "format": decoded_format or "text",
        "encoded": encoded_token,
        "decoded": decoded_text,
    }
