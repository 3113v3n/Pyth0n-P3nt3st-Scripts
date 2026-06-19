"""Reusable helper functions for mobile static scanning."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Iterable

from .android_resource_helpers import (
    build_android_obfuscated_maps,
    is_sensitive_obfuscated_resource_value,
    parse_android_resource_id_literal,
    register_symbol_id,
    scan_obfuscated_resource_references,
)
from .base64_helpers import (
    beautify_decoded_payload,
    build_base64_entry,
    decode_base64_if_interesting,
    is_noise_base64_context,
)
from .file_scan_helpers import scan_single_file
from .ios_plist_helpers import scan_ios_plist
from .manifest_scan_helpers import scan_android_manifest
from .models import Finding
from .scoring_helpers import build_severity_score, dedupe_findings
from .secret_helpers import (
    extract_printable_strings,
    is_probable_version_ip,
    is_valuable_secret_evidence,
    normalize_line_no_truncate,
    read_text_if_possible,
    snippet_around,
)
from .text_indicator_helpers import scan_text_for_indicators
from .url_helpers import (
    canonicalize_url,
    collapse_urls_to_common_bases,
    is_source_repo_reference_url,
    is_valid_url_host,
    is_valuable_url,
    sanitize_url_candidate,
    to_base_url,
)


def _safe_relpath(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * (0.0 if p == 0 else math.log2(p))
    return entropy


def _severity_weight(cls, severity: str) -> int:
    return cls.SEVERITY_WEIGHTS.get(severity.lower(), 1)


def _is_valuable_url(cls, url: str) -> bool:
    return is_valuable_url(cls, url)


def _canonicalize_url(cls, url: str) -> str:
    return canonicalize_url(cls, url)


def _sanitize_url_candidate(cls, url: str) -> str:
    return sanitize_url_candidate(cls, url)


def _is_valid_url_host(cls, host: str) -> bool:
    return is_valid_url_host(cls, host)


def _is_source_repo_reference_url(cls, host: str, path: str) -> bool:
    return is_source_repo_reference_url(cls, host, path)


def _to_base_url(url: str) -> str:
    return to_base_url(url)


def _collapse_urls_to_common_bases(cls, urls: set[str]) -> list[str]:
    return collapse_urls_to_common_bases(urls)


def _snippet_at_index(text: str, index: int, radius: int = 50) -> str:
    start = max(0, index - radius)
    end = min(len(text), index + radius)
    return text[start:end]


def _is_probable_version_ip(cls, ip_text: str, searchable_text: str, match_start: int) -> bool:
    return is_probable_version_ip(cls, ip_text, searchable_text, match_start)


def _is_valuable_secret_evidence(cls, title: str, evidence: str) -> bool:
    return is_valuable_secret_evidence(cls, title, evidence)


def _extract_printable_strings(cls, data: bytes, max_strings: int) -> list[str]:
    return extract_printable_strings(cls, data, max_strings)


def _read_text_if_possible(path: Path) -> str:
    return read_text_if_possible(path)


def _beautify_decoded_payload(payload: str) -> tuple[str, str]:
    return beautify_decoded_payload(payload)


def _is_noise_base64_context(cls, context_window: str) -> bool:
    """Reject obvious base64 noise contexts (images/fonts/media/binary data URIs)."""
    return is_noise_base64_context(cls, context_window)


def _decode_base64_if_interesting(
    cls,
    token: str,
    *,
    context_window: str = "",
) -> tuple[str, str] | None:
    return decode_base64_if_interesting(cls, token, context_window=context_window)


def _build_base64_entry(rel_file: str, encoded_token: str, decoded_text: str, decoded_format: str) -> dict:
    return build_base64_entry(rel_file, encoded_token, decoded_text, decoded_format)


def _snippet_around(text: str, needle: str, radius: int = 80) -> str:
    return snippet_around(text, needle, radius)


def _normalize_line_no_truncate(text: str) -> str:
    return normalize_line_no_truncate(text)


def _parse_android_resource_id_literal(token: str) -> int | None:
    return parse_android_resource_id_literal(token)


def _register_symbol_id(symbol_map: dict[str, set[int]], symbol: str, resource_id: int) -> None:
    register_symbol_id(symbol_map, symbol, resource_id)


def _build_android_obfuscated_maps(self, root: Path) -> tuple[dict[int, dict], dict[str, set[int]]]:
    return build_android_obfuscated_maps(
        self,
        root,
        safe_relpath=self._safe_relpath,
        parse_resource_id=self._parse_android_resource_id_literal,
        read_text=_read_text_if_possible,
        register_symbol_id=self._register_symbol_id,
    )


def _is_sensitive_obfuscated_resource_value(cls, resource_name: str, resource_value: str) -> bool:
    return is_sensitive_obfuscated_resource_value(cls, resource_name, resource_value)


def _scan_obfuscated_resource_references(self, text: str, rel_file: str) -> tuple[list[dict], list[Finding]]:
    resource_map = getattr(self, "_android_obfuscated_resource_map", {}) or {}
    symbol_map = getattr(self, "_android_obfuscated_symbol_map", {}) or {}
    return scan_obfuscated_resource_references(self, text, rel_file, resource_map, symbol_map)


def _scan_text_for_indicators(self, text: str, rel_file: str) -> tuple[list[Finding], list[Finding]]:
    return scan_text_for_indicators(self, text, rel_file)


def _scan_single_file(self, file_path: Path, root: Path) -> dict:
    return scan_single_file(
        self,
        file_path,
        root,
        safe_relpath=self._safe_relpath,
        extract_printable_strings=lambda data, max_strings: self._extract_printable_strings(data, max_strings),
        is_valuable_url=self._is_valuable_url,
        canonicalize_url=self._canonicalize_url,
        is_probable_version_ip=self._is_probable_version_ip,
        normalize_line_no_truncate=self._normalize_line_no_truncate,
        is_valuable_secret_evidence=self._is_valuable_secret_evidence,
        scan_obfuscated_resource_references=lambda text, rel_file: self._scan_obfuscated_resource_references(text, rel_file),
        decode_base64_if_interesting=lambda token, context_window="": self._decode_base64_if_interesting(token, context_window=context_window),
        build_base64_entry=self._build_base64_entry,
        scan_text_for_indicators=lambda text, rel_file: self._scan_text_for_indicators(text, rel_file),
    )


def _scan_android_manifest(self, root: Path) -> tuple[list[Finding], list[Finding]]:
    return scan_android_manifest(
        self,
        root,
        safe_relpath=self._safe_relpath,
        read_text_if_possible=self._read_text_if_possible,
    )


def _scan_ios_plist(self, root: Path) -> tuple[list[Finding], list[Finding]]:
    return scan_ios_plist(
        root,
        safe_relpath=self._safe_relpath,
        read_text_if_possible=self._read_text_if_possible,
    )


def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    return dedupe_findings(findings)


def _build_severity_score(cls, findings: list[Finding]) -> dict:
    return build_severity_score(cls, findings)
