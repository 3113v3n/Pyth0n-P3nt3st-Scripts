"""Post-processing helpers for mobile scan findings."""

from __future__ import annotations

from .models import Finding


def finalize_mobile_findings(
    *,
    hardcoded: list[Finding],
    risk_findings: list[Finding],
    control_findings: list[Finding],
    urls: set[str],
    assess_discovered_api_keys,
    dedupe_findings,
) -> dict:
    hardcoded = dedupe_findings(hardcoded)
    risk_findings = dedupe_findings(risk_findings)
    control_findings = dedupe_findings(control_findings)

    api_key_findings, api_key_report_lines = assess_discovered_api_keys(hardcoded)
    if api_key_findings:
        risk_findings.extend(api_key_findings)
        risk_findings = dedupe_findings(risk_findings)

    has_https_endpoint = any(url.lower().startswith("https://") for url in urls)
    has_pinning_signal = any(f.category == "pinning" for f in control_findings)
    if has_https_endpoint and not has_pinning_signal:
        risk_findings.append(
            Finding(
                category="pinning",
                title="No Certificate Pinning Signal Detected (Heuristic)",
                severity="low",
                file="global",
                evidence="HTTPS endpoints discovered, but no static pinning signal matched.",
            )
        )
        risk_findings = dedupe_findings(risk_findings)

    combined_risk_findings = dedupe_findings(risk_findings + hardcoded)

    return {
        "hardcoded": hardcoded,
        "risk_findings": risk_findings,
        "control_findings": control_findings,
        "api_key_findings": api_key_findings,
        "api_key_report_lines": api_key_report_lines,
        "combined_risk_findings": combined_risk_findings,
    }
