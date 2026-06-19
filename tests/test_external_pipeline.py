from utils.external.external_constants import SAFE_MAX_TARGETS_PER_PHASE, SAFE_MODE_ALLOWED_PHASES
from utils.external.external_pipeline import ExternalPipeline


def test_effective_phases_safe_mode_filters_and_falls_back_to_safe_defaults():
    effective, dropped = ExternalPipeline._effective_phases(("ports", "vulns"), safe_mode=True)

    assert effective == SAFE_MODE_ALLOWED_PHASES
    assert dropped == ("ports", "vulns")


def test_build_scoped_hosts_file_filters_deduplicates_and_caps_targets(tmp_path):
    in_scope_hosts = "\n".join(
        [f"api{i}.example.com" for i in range(SAFE_MAX_TARGETS_PER_PHASE + 5)]
    )
    source = tmp_path / "targets.txt"
    source.write_text(
        "\n".join(
            [
                "https://www.example.com/path",
                "www.example.com",
                "api.example.com extra-column",
                "outside.test",
                in_scope_hosts,
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    pipeline = object.__new__(ExternalPipeline)
    warnings = []
    pipeline.print_warning_message = lambda message, file_path=None: warnings.append((message, file_path))

    scoped_file = pipeline._build_scoped_hosts_file(
        source_file=source,
        target_domain="example.com",
        run_dir=tmp_path,
        label="probe",
        safe_mode=True,
    )

    assert scoped_file is not None
    scoped_hosts = scoped_file.read_text(encoding="utf-8").splitlines()
    assert len(scoped_hosts) == SAFE_MAX_TARGETS_PER_PHASE
    assert all(host == "example.com" or host.endswith(".example.com") for host in scoped_hosts)
    assert "outside.test" not in scoped_hosts
    assert scoped_hosts.count("www.example.com") == 1
    assert warnings
