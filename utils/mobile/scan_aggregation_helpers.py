"""Helpers for aggregating per-file mobile scan results."""

from __future__ import annotations

from collections.abc import Iterable


def aggregate_scan_results(scanned_results: Iterable[dict]) -> dict:
    urls: set[str] = set()
    ips: set[str] = set()
    hardcoded = []
    obfuscated_refs = []
    base64_entries = []
    risk_findings = []
    control_findings = []
    bytes_scanned = 0
    files_skipped = 0

    for scanned in scanned_results:
        if scanned["skipped"]:
            files_skipped += 1
            continue

        bytes_scanned += scanned["bytes_scanned"]
        urls.update(scanned["urls"])
        ips.update(scanned["ips"])
        hardcoded.extend(scanned["hardcoded"])
        obfuscated_refs.extend(scanned.get("obfuscated_refs", []))
        base64_entries.extend(scanned["base64"])
        risk_findings.extend(scanned["risk_findings"])
        control_findings.extend(scanned["control_findings"])

    return {
        "urls": urls,
        "ips": ips,
        "hardcoded": hardcoded,
        "obfuscated_refs": obfuscated_refs,
        "base64_entries": base64_entries,
        "risk_findings": risk_findings,
        "control_findings": control_findings,
        "bytes_scanned": bytes_scanned,
        "files_skipped": files_skipped,
    }
