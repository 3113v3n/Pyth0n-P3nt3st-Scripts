from utils.mobile.models import Finding


def _constants():
    class Constants:
        SEVERITY_WEIGHTS = {
            "critical": 5,
            "high": 4,
            "medium": 3,
            "low": 2,
            "info": 1,
        }

        @classmethod
        def _severity_weight(cls, severity: str) -> int:
            return cls.SEVERITY_WEIGHTS.get(severity.lower(), 1)

    return Constants


def test_dedupe_findings_removes_duplicates_and_orders_stably():
    from utils.mobile.scoring_helpers import dedupe_findings

    findings = [
        Finding("network_security", "B", "high", "b.txt", "bbb"),
        Finding("network_security", "B", "high", "b.txt", "bbb"),
        Finding("debugging", "A", "low", "a.txt", "aaa"),
    ]

    deduped = dedupe_findings(findings)

    assert len(deduped) == 2
    assert [(f.severity, f.category, f.title) for f in deduped] == [
        ("high", "network_security", "B"),
        ("low", "debugging", "A"),
    ]


def test_build_severity_score_computes_breakdown_and_band():
    from utils.mobile.scoring_helpers import build_severity_score

    constants = _constants()
    findings = [
        Finding("a", "A", "critical", "a.txt", "1"),
        Finding("b", "B", "high", "b.txt", "2"),
        Finding("c", "C", "unknown", "c.txt", "3"),
    ]

    score = build_severity_score(constants, findings)

    assert score["weighted_total"] == 10
    assert score["risk_score"] == 25
    assert score["security_posture_score"] == 75
    assert score["risk_band"] == "low"
    assert score["severity_breakdown"] == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 1,
    }
