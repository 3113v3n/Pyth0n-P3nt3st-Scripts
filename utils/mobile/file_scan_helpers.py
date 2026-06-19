"""Single-file mobile scan helper extracted from static scan helpers."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from .models import Finding


def scan_single_file(
    constants,
    file_path: Path,
    root: Path,
    *,
    safe_relpath,
    extract_printable_strings,
    is_valuable_url,
    canonicalize_url,
    is_probable_version_ip,
    normalize_line_no_truncate,
    is_valuable_secret_evidence,
    scan_obfuscated_resource_references,
    decode_base64_if_interesting,
    build_base64_entry,
    scan_text_for_indicators,
) -> dict:
    rel_file = safe_relpath(file_path, root)
    suffix = file_path.suffix.lower()

    result = {
        "file": rel_file,
        "urls": set(),
        "ips": set(),
        "hardcoded": [],
        "obfuscated_refs": [],
        "base64": [],
        "risk_findings": [],
        "control_findings": [],
        "bytes_scanned": 0,
        "skipped": False,
    }

    try:
        stat = file_path.stat()
    except OSError:
        result["skipped"] = True
        return result

    if suffix in constants.BINARY_SKIP_EXTENSIONS and stat.st_size > constants.MAX_FILE_SIZE_BYTES:
        result["skipped"] = True
        return result

    if stat.st_size > constants.MAX_FILE_SIZE_BYTES:
        result["skipped"] = True
        return result

    try:
        data = file_path.read_bytes()
    except OSError:
        result["skipped"] = True
        return result

    result["bytes_scanned"] = len(data)

    text_parts: list[str] = []
    decoded_text = ""
    if suffix in constants.TEXT_EXTENSIONS:
        try:
            decoded_text = data.decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = ""
        if decoded_text:
            text_parts.append(decoded_text)

    if not decoded_text:
        printable = extract_printable_strings(data, constants.MAX_STRINGS_PER_FILE)
        if printable:
            text_parts.append("\n".join(printable))

    if not text_parts:
        return result

    searchable = "\n".join(text_parts)
    if len(searchable) > constants.MAX_TEXT_CHARS_PER_FILE:
        searchable = searchable[: constants.MAX_TEXT_CHARS_PER_FILE]

    for match in constants.URL_RE.findall(searchable):
        if is_valuable_url(match):
            canonical_url = canonicalize_url(match)
            if canonical_url:
                result["urls"].add(canonical_url)

    for match_obj in constants.IP_RE.finditer(searchable):
        match = match_obj.group(0)
        try:
            ip_obj = ipaddress.ip_address(match)
            if (
                not ip_obj.is_loopback
                and not ip_obj.is_multicast
                and not ip_obj.is_unspecified
                and not ip_obj.is_reserved
            ):
                if is_probable_version_ip(match, searchable, match_obj.start()):
                    continue
                result["ips"].add(match)
        except ValueError:
            continue

    for title, severity, pattern in constants.SECRET_PATTERNS:
        for m in pattern.finditer(searchable):
            evidence = normalize_line_no_truncate(m.group(0))
            if not is_valuable_secret_evidence(title, evidence):
                continue
            result["hardcoded"].append(
                Finding(
                    category="hardcoded_secret",
                    title=title,
                    severity=severity,
                    file=rel_file,
                    evidence=evidence,
                )
            )

    obfuscated_refs, obfuscated_findings = scan_obfuscated_resource_references(searchable, rel_file)
    if obfuscated_refs:
        result["obfuscated_refs"].extend(obfuscated_refs)
    if obfuscated_findings:
        result["hardcoded"].extend(obfuscated_findings)

    seen_b64 = set()
    for token_match in constants.BASE64_TOKEN_RE.finditer(searchable):
        token = token_match.group(0)
        if token in seen_b64:
            continue
        seen_b64.add(token)
        context_start = max(0, token_match.start() - 160)
        context_end = min(len(searchable), token_match.end() + 32)
        context_window = searchable[context_start:context_end]
        decoded_payload = decode_base64_if_interesting(token, context_window=context_window)
        if decoded_payload:
            decoded_text, decoded_format = decoded_payload
            result["base64"].append(
                build_base64_entry(rel_file, token, decoded_text, decoded_format)
            )

    for url in result["urls"]:
        if url.lower().startswith("http://"):
            result["risk_findings"].append(
                Finding(
                    category="network_security",
                    title="Potential Cleartext Backend Endpoint",
                    severity="medium",
                    file=rel_file,
                    evidence=normalize_line_no_truncate(url),
                )
            )

    risks, controls = scan_text_for_indicators(searchable, rel_file)
    result["risk_findings"].extend(risks)
    result["control_findings"].extend(controls)

    return result
