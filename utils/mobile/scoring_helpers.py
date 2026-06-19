"""Finding dedupe and scoring helpers extracted from mobile static scan helpers."""

from __future__ import annotations

from collections.abc import Iterable

from .models import Finding


def dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
    unique = {}
    for finding in findings:
        key = (finding.category, finding.title, finding.severity, finding.file, finding.evidence)
        unique[key] = finding
    ordered_keys = sorted(
        unique,
        key=lambda item: (
            str(item[2]).lower(),
            str(item[0]).lower(),
            str(item[1]).lower(),
            str(item[3]).lower(),
            str(item[4]).lower(),
        ),
    )
    return [unique[key] for key in ordered_keys]



def build_severity_score(constants, findings: list[Finding]) -> dict:
    severity_counts: dict[str, int] = {key: 0 for key in constants.SEVERITY_WEIGHTS}
    weighted_total = 0

    for finding in findings:
        sev = finding.severity.lower()
        if sev not in severity_counts:
            sev = "info"
        severity_counts[sev] += 1
        weighted_total += constants._severity_weight(sev)

    risk_score = min(100, int(round(weighted_total * 2.5)))
    security_posture_score = max(0, 100 - risk_score)

    if risk_score >= 85:
        risk_band = "critical"
    elif risk_score >= 65:
        risk_band = "high"
    elif risk_score >= 40:
        risk_band = "medium"
    elif risk_score >= 20:
        risk_band = "low"
    else:
        risk_band = "informational"

    return {
        "risk_score": risk_score,
        "security_posture_score": security_posture_score,
        "risk_band": risk_band,
        "weighted_total": weighted_total,
        "severity_breakdown": severity_counts,
    }
