
from utils.mobile.models import Finding


def test_build_reports_map_includes_only_nonzero_entries(tmp_path):
    from utils.mobile.summary_helpers import build_reports_map

    reports = build_reports_map(
        urls_file=tmp_path / "urls.txt",
        ips_file=tmp_path / "ips.txt",
        hardcoded_file=tmp_path / "hardcoded.txt",
        api_key_report_file=tmp_path / "api.txt",
        base64_file=tmp_path / "base64.txt",
        obfuscated_map_file=tmp_path / "obf.txt",
        risk_file=tmp_path / "risk.txt",
        control_file=tmp_path / "control.txt",
        taxonomy_file=tmp_path / "taxonomy.json",
        url_count=2,
        ip_count=0,
        hardcoded_count=3,
        api_key_assessment_count=0,
        base64_count=1,
        obfuscated_map_count=0,
        risk_count=4,
        control_count=0,
        taxonomy_tagged_count=5,
    )

    assert reports == {
        "urls": str(tmp_path / "urls.txt"),
        "hardcoded": str(tmp_path / "hardcoded.txt"),
        "base64": str(tmp_path / "base64.txt"),
        "integrity_findings": str(tmp_path / "risk.txt"),
        "masvs_mastg": str(tmp_path / "taxonomy.json"),
    }


def test_summarize_findings_builds_top_risks_and_controls():
    from utils.mobile.summary_helpers import summarize_findings

    combined = [
        Finding("network_security", "Cleartext", "medium", "a.txt", "1"),
        Finding("network_security", "Cleartext", "medium", "b.txt", "2"),
        Finding("pinning", "No Pinning", "low", "c.txt", "3"),
    ]
    controls = [
        Finding("pinning", "Pinset Present", "info", "a.txt", "x"),
        Finding("pinning", "Pinset Present", "info", "b.txt", "y"),
    ]

    top_risks, top_controls = summarize_findings(combined, controls)

    assert top_risks == ["Cleartext (medium): 2", "No Pinning (low): 1"]
    assert top_controls == ["Pinset Present: 2"]


def test_build_scan_summary_hashes_application_and_embeds_scoring(tmp_path):
    from utils.mobile.summary_helpers import build_scan_summary

    app = tmp_path / "app.apk"
    app.write_bytes(b"apk-bytes")

    summary = build_scan_summary(
        application=app,
        platform="android",
        extraction_method="fresh",
        output_directory="/tmp/output",
        files_scanned=10,
        files_skipped=2,
        bytes_scanned=1000,
        url_count=3,
        ip_count=1,
        hardcoded_count=4,
        api_key_assessment_count=1,
        api_key_issue_count=1,
        base64_count=2,
        obfuscated_string_refs_count=5,
        risk_count=6,
        control_count=7,
        combined_risk_count=8,
        top_risks=["a: 1"],
        top_controls=["b: 2"],
        scoring={"risk_score": 25},
        nuclei={"status": "ok"},
        taxonomy_mode="both",
        taxonomy_profile="balanced",
        taxonomy_tagged_count=9,
        reports={"urls": "/tmp/output/urls.txt"},
    )

    assert summary["application"] == "app.apk"
    assert summary["platform"] == "android"
    assert summary["application_sha256"]
    assert summary["scoring"] == {"risk_score": 25}
    assert summary["reports"] == {"urls": "/tmp/output/urls.txt"}
