"""Thin compatibility mixin for mobile static scan behavior.

Large scanner internals were extracted into helper/constant modules to keep this
mixin lean while preserving the same method names used by mobile command flows.
"""

from __future__ import annotations

from .static_scan_constants import MobileStaticScanConstants
from .static_scan_helpers import (
    _beautify_decoded_payload,
    _build_android_obfuscated_maps,
    _build_base64_entry,
    _build_severity_score,
    _canonicalize_url,
    _collapse_urls_to_common_bases,
    _decode_base64_if_interesting,
    _dedupe_findings,
    _entropy,
    _extract_printable_strings,
    _is_noise_base64_context,
    _is_probable_version_ip,
    _is_source_repo_reference_url,
    _is_valid_url_host,
    _is_valuable_secret_evidence,
    _is_valuable_url,
    _normalize_line_no_truncate,
    _parse_android_resource_id_literal,
    _read_text_if_possible,
    _register_symbol_id,
    _safe_relpath,
    _sanitize_url_candidate,
    _scan_android_manifest,
    _scan_obfuscated_resource_references,
    _scan_ios_plist,
    _scan_single_file,
    _scan_text_for_indicators,
    _severity_weight,
    _is_sensitive_obfuscated_resource_value,
    _snippet_around,
    _snippet_at_index,
    _to_base_url,
)


class MobileStaticScanMixin(MobileStaticScanConstants):
    """Compatibility mixin preserving static-scan API surface."""

    _safe_relpath = staticmethod(_safe_relpath)
    _entropy = staticmethod(_entropy)
    _severity_weight = classmethod(_severity_weight)
    _is_valuable_url = classmethod(_is_valuable_url)
    _canonicalize_url = classmethod(_canonicalize_url)
    _sanitize_url_candidate = classmethod(_sanitize_url_candidate)
    _is_valid_url_host = classmethod(_is_valid_url_host)
    _is_source_repo_reference_url = classmethod(_is_source_repo_reference_url)
    _to_base_url = staticmethod(_to_base_url)
    _collapse_urls_to_common_bases = classmethod(_collapse_urls_to_common_bases)
    _snippet_at_index = staticmethod(_snippet_at_index)
    _is_probable_version_ip = classmethod(_is_probable_version_ip)
    _is_valuable_secret_evidence = classmethod(_is_valuable_secret_evidence)
    _extract_printable_strings = classmethod(_extract_printable_strings)
    _read_text_if_possible = staticmethod(_read_text_if_possible)
    _beautify_decoded_payload = staticmethod(_beautify_decoded_payload)
    _is_noise_base64_context = classmethod(_is_noise_base64_context)
    _decode_base64_if_interesting = classmethod(_decode_base64_if_interesting)
    _build_base64_entry = staticmethod(_build_base64_entry)
    _snippet_around = staticmethod(_snippet_around)
    _normalize_line_no_truncate = staticmethod(_normalize_line_no_truncate)
    _parse_android_resource_id_literal = staticmethod(_parse_android_resource_id_literal)
    _register_symbol_id = staticmethod(_register_symbol_id)
    _build_android_obfuscated_maps = _build_android_obfuscated_maps
    _is_sensitive_obfuscated_resource_value = classmethod(_is_sensitive_obfuscated_resource_value)
    _scan_obfuscated_resource_references = _scan_obfuscated_resource_references
    _scan_text_for_indicators = _scan_text_for_indicators
    _scan_single_file = _scan_single_file
    _scan_android_manifest = _scan_android_manifest
    _scan_ios_plist = _scan_ios_plist
    _dedupe_findings = staticmethod(_dedupe_findings)
    _build_severity_score = classmethod(_build_severity_score)
