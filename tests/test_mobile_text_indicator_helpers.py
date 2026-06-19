import re


def _constants():
    class Constants:
        RISK_INDICATORS = [
            (
                "webview",
                "Potentially Unsafe WebView Usage",
                "medium",
                ("setjavascriptenabled(true)",),
            )
        ]
        ADVANCED_RISK_REGEX = [
            (
                "crypto",
                "Weak Hash Algorithm Usage",
                "high",
                re.compile(r"(?i)md5"),
            )
        ]
        CONTROL_INDICATORS = [
            (
                "pinning",
                "Certificate Pinning Signal",
                "info",
                ("certificatepinner",),
            )
        ]

        @staticmethod
        def clean_line(text: str) -> str:
            return " ".join(str(text).split())

        @staticmethod
        def _snippet_around(text: str, needle: str, radius: int = 80) -> str:
            index = text.find(needle)
            if index < 0:
                return needle
            start = max(0, index - radius)
            end = min(len(text), index + len(needle) + radius)
            return text[start:end]

    return Constants


def test_scan_text_for_indicators_collects_risks_and_controls():
    from utils.mobile.text_indicator_helpers import scan_text_for_indicators

    constants = _constants()
    text = "setJavaScriptEnabled(true) uses md5 and also CertificatePinner for TLS"

    risks, controls = scan_text_for_indicators(constants, text, "src/app.java")

    assert len(risks) == 2
    assert {risk.category for risk in risks} == {"webview", "crypto"}
    assert len(controls) == 1
    assert controls[0].category == "pinning"
    assert controls[0].file == "src/app.java"


def test_scan_text_for_indicators_returns_empty_when_no_matches():
    from utils.mobile.text_indicator_helpers import scan_text_for_indicators

    constants = _constants()

    risks, controls = scan_text_for_indicators(constants, "harmless content only", "src/app.java")

    assert risks == []
    assert controls == []
