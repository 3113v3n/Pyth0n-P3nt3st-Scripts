from utils.mobile.models import Finding


def test_finalize_mobile_findings_adds_api_findings_and_pinning_heuristic():
    from utils.mobile.finding_pipeline_helpers import finalize_mobile_findings

    hardcoded = [
        Finding("hardcoded_secret", "API Key", "high", "a.txt", "secret=abc123"),
    ]
    risks = [
        Finding("network_security", "Cleartext Backend", "medium", "b.txt", "http://x"),
    ]
    controls = []
    urls = {"https://secure.example", "http://legacy.example"}

    api_key_findings = [
        Finding("api_keys", "Google API Key Exposed", "high", "a.txt", "AIza..."),
    ]

    result = finalize_mobile_findings(
        hardcoded=hardcoded,
        risk_findings=risks,
        control_findings=controls,
        urls=urls,
        assess_discovered_api_keys=lambda findings: (api_key_findings, ["checklist"]),
        dedupe_findings=lambda findings: list({(f.category, f.title, f.severity, f.file, f.evidence): f for f in findings}.values()),
    )

    assert result["api_key_findings"] == api_key_findings
    assert result["api_key_report_lines"] == ["checklist"]
    assert any(f.title == "No Certificate Pinning Signal Detected (Heuristic)" for f in result["risk_findings"])
    assert any(f.title == "Google API Key Exposed" for f in result["risk_findings"])
    assert len(result["combined_risk_findings"]) >= 3


def test_finalize_mobile_findings_skips_pinning_heuristic_when_control_present():
    from utils.mobile.finding_pipeline_helpers import finalize_mobile_findings

    controls = [Finding("pinning", "Certificate Pinset Declared", "info", "cfg.xml", "pin-set")]

    result = finalize_mobile_findings(
        hardcoded=[],
        risk_findings=[],
        control_findings=controls,
        urls={"https://secure.example"},
        assess_discovered_api_keys=lambda findings: ([], []),
        dedupe_findings=lambda findings: findings,
    )

    assert not any(f.title == "No Certificate Pinning Signal Detected (Heuristic)" for f in result["risk_findings"])
    assert result["control_findings"] == controls
