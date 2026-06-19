

def test_build_artifact_paths_uses_expected_suffixes(tmp_path):
    from utils.mobile.report_artifact_helpers import build_artifact_paths

    paths = build_artifact_paths(tmp_path / "scan_android")

    assert paths["urls"] == tmp_path / "scan_android_urls.txt"
    assert paths["ips"] == tmp_path / "scan_android_ips.txt"
    assert paths["hardcoded"] == tmp_path / "scan_android_hardcoded.txt"
    assert paths["summary"] == tmp_path / "scan_android_summary.json"
    assert paths["taxonomy"] == tmp_path / "scan_android_masvs_mastg.json"


def test_write_taxonomy_report_writes_entries_and_returns_count(tmp_path):
    from utils.mobile.report_artifact_helpers import write_taxonomy_report

    taxonomy_file = tmp_path / "taxonomy.json"
    report = {"entries": [{"id": 1}], "meta": {"mode": "both"}}

    count = write_taxonomy_report(taxonomy_file, report)

    assert count == 1
    assert taxonomy_file.exists()
    assert '"entries"' in taxonomy_file.read_text(encoding="utf-8")


def test_write_taxonomy_report_skips_empty_entries(tmp_path):
    from utils.mobile.report_artifact_helpers import write_taxonomy_report

    taxonomy_file = tmp_path / "taxonomy.json"
    report = {"entries": []}

    count = write_taxonomy_report(taxonomy_file, report)

    assert count == 0
    assert not taxonomy_file.exists()
