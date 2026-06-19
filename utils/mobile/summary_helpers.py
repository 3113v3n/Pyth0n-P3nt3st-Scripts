"""Summary/report assembly helpers for mobile command orchestration."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import Finding


def build_reports_map(
    *,
    urls_file: Path,
    ips_file: Path,
    hardcoded_file: Path,
    api_key_report_file: Path,
    base64_file: Path,
    obfuscated_map_file: Path,
    risk_file: Path,
    control_file: Path,
    taxonomy_file: Path,
    url_count: int,
    ip_count: int,
    hardcoded_count: int,
    api_key_assessment_count: int,
    base64_count: int,
    obfuscated_map_count: int,
    risk_count: int,
    control_count: int,
    taxonomy_tagged_count: int,
) -> dict[str, str]:
    reports = {}
    if url_count:
        reports["urls"] = str(urls_file)
    if ip_count:
        reports["ips"] = str(ips_file)
    if hardcoded_count:
        reports["hardcoded"] = str(hardcoded_file)
    if api_key_assessment_count:
        reports["api_key_checklist"] = str(api_key_report_file)
    if base64_count:
        reports["base64"] = str(base64_file)
    if obfuscated_map_count:
        reports["obfuscated_string_map"] = str(obfuscated_map_file)
    if risk_count:
        reports["integrity_findings"] = str(risk_file)
    if control_count:
        reports["integrity_controls"] = str(control_file)
    if taxonomy_tagged_count:
        reports["masvs_mastg"] = str(taxonomy_file)
    return reports



def summarize_findings(
    combined_risk_findings: list[Finding],
    control_findings: list[Finding],
) -> tuple[list[str], list[str]]:
    risk_counter = {}
    for finding in combined_risk_findings:
        key = f"{finding.title} ({finding.severity})"
        risk_counter[key] = risk_counter.get(key, 0) + 1

    control_counter = {}
    for finding in control_findings:
        key = f"{finding.title}"
        control_counter[key] = control_counter.get(key, 0) + 1

    top_risks = [f"{k}: {v}" for k, v in sorted(risk_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
    top_controls = [f"{k}: {v}" for k, v in sorted(control_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
    return top_risks, top_controls



def build_scan_summary(
    *,
    application: Path,
    platform: str,
    extraction_method: str,
    output_directory: str,
    files_scanned: int,
    files_skipped: int,
    bytes_scanned: int,
    url_count: int,
    ip_count: int,
    hardcoded_count: int,
    api_key_assessment_count: int,
    api_key_issue_count: int,
    base64_count: int,
    obfuscated_string_refs_count: int,
    risk_count: int,
    control_count: int,
    combined_risk_count: int,
    top_risks: list[str],
    top_controls: list[str],
    scoring: dict,
    nuclei: dict,
    taxonomy_mode: str,
    taxonomy_profile: str,
    taxonomy_tagged_count: int,
    reports: dict[str, str],
) -> dict:
    return {
        "application": application.name,
        "application_sha256": hashlib.sha256(application.read_bytes()).hexdigest(),
        "platform": platform,
        "extraction_method": extraction_method,
        "output_directory": output_directory,
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "bytes_scanned": bytes_scanned,
        "url_count": url_count,
        "ip_count": ip_count,
        "hardcoded_count": hardcoded_count,
        "api_key_assessment_count": api_key_assessment_count,
        "api_key_issue_count": api_key_issue_count,
        "base64_count": base64_count,
        "obfuscated_string_refs_count": obfuscated_string_refs_count,
        "risk_count": risk_count,
        "control_count": control_count,
        "combined_risk_count": combined_risk_count,
        "top_risks": top_risks,
        "top_controls": top_controls,
        "scoring": scoring,
        "nuclei": nuclei,
        "taxonomy_mode": taxonomy_mode,
        "taxonomy_profile": taxonomy_profile,
        "taxonomy_tagged_count": taxonomy_tagged_count,
        "reports": reports,
    }
