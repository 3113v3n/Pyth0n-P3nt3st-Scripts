def test_resolve_bootstrap_paths_uses_project_root_and_platform_python_name(tmp_path):
    from handlers.package_bootstrap import resolve_bootstrap_paths

    paths = resolve_bootstrap_paths(
        project_root=tmp_path,
        venv_name=".venv",
        requirements_file="requirements.txt",
        os_name="posix",
    )

    assert paths.root == tmp_path.resolve()
    assert paths.venv_dir == tmp_path.resolve() / ".venv"
    assert paths.venv_python == tmp_path.resolve() / ".venv/bin/python"
    assert paths.requirements_file == tmp_path.resolve() / "requirements.txt"


def test_is_running_in_project_venv_detects_matching_prefix(tmp_path):
    from handlers.package_bootstrap import is_running_in_project_venv

    venv_dir = tmp_path / ".venv"
    inside_prefix = venv_dir / "lib/python3.13"
    inside_prefix.mkdir(parents=True)

    assert is_running_in_project_venv(inside_prefix, venv_dir) is True
    assert is_running_in_project_venv(tmp_path / "elsewhere", venv_dir) is False


def test_requirements_stamp_round_trip(tmp_path):
    from handlers.package_bootstrap import requirements_stamp_matches, write_requirements_stamp

    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("pytest==9.1.0\n", encoding="utf-8")

    assert requirements_stamp_matches(venv_dir, requirements_file) is False

    write_requirements_stamp(venv_dir, requirements_file)

    assert requirements_stamp_matches(venv_dir, requirements_file) is True

    requirements_file.write_text("pytest==9.2.0\n", encoding="utf-8")
    assert requirements_stamp_matches(venv_dir, requirements_file) is False


def test_install_requirements_into_venv_runs_pip_and_writes_stamp(tmp_path, monkeypatch):
    from handlers.package_bootstrap import (
        install_requirements_into_venv,
        requirements_stamp_matches,
    )

    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    venv_python = venv_dir / "bin/python"
    venv_python.parent.mkdir(parents=True)
    venv_python.write_text("", encoding="utf-8")
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("pytest==9.1.0\n", encoding="utf-8")

    calls = []

    def fake_run(command, check):
        calls.append((command, check))
        return None

    monkeypatch.setattr("handlers.package_bootstrap.subprocess.run", fake_run)

    install_requirements_into_venv(venv_python, requirements_file, venv_dir)

    assert calls == [([
        str(venv_python),
        "-m",
        "pip",
        "install",
        "-r",
        str(requirements_file),
    ], True)]
    assert requirements_stamp_matches(venv_dir, requirements_file) is True
