from utils.mobile.models import Finding


def test_aggregate_scan_results_combines_sets_lists_and_counts():
    from utils.mobile.scan_aggregation_helpers import aggregate_scan_results

    scanned_results = [
        {
            "skipped": False,
            "bytes_scanned": 100,
            "urls": {"https://a.example", "http://b.example"},
            "ips": {"1.1.1.1"},
            "hardcoded": [Finding("hardcoded_secret", "A", "high", "a.txt", "x")],
            "obfuscated_refs": [{"token": "0x7f110001"}],
            "base64": [{"decoded": "abc"}],
            "risk_findings": [Finding("network_security", "R1", "medium", "a.txt", "e1")],
            "control_findings": [Finding("pinning", "C1", "info", "a.txt", "e2")],
        },
        {
            "skipped": True,
            "bytes_scanned": 999,
            "urls": {"https://ignored.example"},
            "ips": {"8.8.8.8"},
            "hardcoded": [],
            "obfuscated_refs": [],
            "base64": [],
            "risk_findings": [],
            "control_findings": [],
        },
        {
            "skipped": False,
            "bytes_scanned": 50,
            "urls": {"https://a.example", "https://c.example"},
            "ips": {"2.2.2.2"},
            "hardcoded": [Finding("hardcoded_secret", "B", "medium", "b.txt", "y")],
            "obfuscated_refs": [{"token": "0x7f110002"}],
            "base64": [{"decoded": "def"}],
            "risk_findings": [Finding("network_security", "R2", "low", "b.txt", "e3")],
            "control_findings": [],
        },
    ]

    result = aggregate_scan_results(scanned_results)

    assert result["files_skipped"] == 1
    assert result["bytes_scanned"] == 150
    assert result["urls"] == {"https://a.example", "http://b.example", "https://c.example"}
    assert result["ips"] == {"1.1.1.1", "2.2.2.2"}
    assert len(result["hardcoded"]) == 2
    assert result["obfuscated_refs"] == [{"token": "0x7f110001"}, {"token": "0x7f110002"}]
    assert result["base64_entries"] == [{"decoded": "abc"}, {"decoded": "def"}]
    assert len(result["risk_findings"]) == 2
    assert len(result["control_findings"]) == 1
