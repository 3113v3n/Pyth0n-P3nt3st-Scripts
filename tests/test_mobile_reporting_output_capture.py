from handlers.messages import DisplayHandler
from handlers.screen import ScreenHandler
from utils.mobile.reporting import MobileReportingMixin


class _MobileReportingHarness(DisplayHandler, MobileReportingMixin):
    pass


def test_console_summary_routes_top_risk_and_control_rows_to_transcript_when_stdout_is_suppressed(capsys):
    harness = _MobileReportingHarness()
    summary = {
        "package_name": "demo.apk",
        "platform": "android",
        "files_scanned": 5,
        "files_skipped": 0,
        "url_count": 1,
        "ip_count": 0,
        "hardcoded_count": 2,
        "api_key_assessment_count": 0,
        "api_key_issue_count": 0,
        "base64_count": 1,
        "obfuscated_string_refs_count": 0,
        "risk_count": 3,
        "control_count": 2,
        "taxonomy_tagged_count": 0,
        "top_risks": ["Cleartext (medium): 2"],
        "top_controls": ["Pinset Present: 1"],
        "scoring": {"risk_score": 20, "security_posture_score": 80, "risk_band": "medium"},
        "taxonomy_mode": "none",
    }

    ScreenHandler.clear_output_transcript()
    DisplayHandler.set_stdout_suppressed(True)
    try:
        harness._console_summary(summary)
    finally:
        DisplayHandler.set_stdout_suppressed(False)

    captured = capsys.readouterr()
    transcript = ScreenHandler.consume_output_transcript()

    assert captured.out == ""
    assert "Top risk findings:" in transcript
    assert "- Cleartext (medium): 2" in transcript
    assert "Detected integrity/security controls:" in transcript
    assert "- Pinset Present: 1" in transcript
