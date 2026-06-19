import os


def test_prepend_paths_to_env_inserts_missing_paths_at_front_without_duplicates():
    from handlers.package_env import prepend_paths_to_env

    env = {"PATH": "/usr/bin:/bin"}
    updated = prepend_paths_to_env(env, ["/custom/bin", "/usr/bin", "", "/opt/bin"])

    assert updated["PATH"].split(os.pathsep) == [
        "/custom/bin",
        "/opt/bin",
        "/usr/bin",
        "/bin",
    ]


def test_tool_install_env_sets_language_tool_homes_and_path(tmp_path):
    from handlers.package_env import build_tool_install_env

    tools_root = tmp_path / "tools"
    env = build_tool_install_env(
        base_env={"PATH": "/usr/bin"},
        tools_root=tools_root,
        bin_dir=tools_root / "bin",
        ruby_bin_dirs=["/opt/homebrew/opt/ruby/bin"],
    )

    assert env["GOBIN"] == str(tools_root / "bin")
    assert env["GOPATH"] == str(tools_root / "go")
    assert env["GEM_HOME"] == str(tools_root / "gems")
    assert env["GEM_PATH"] == str(tools_root / "gems")
    assert env["PIPX_HOME"] == str(tools_root / "pipx")
    assert env["PIPX_BIN_DIR"] == str(tools_root / "bin")
    assert env["PATH"].split(os.pathsep) == [
        str(tools_root / "bin"),
        "/opt/homebrew/opt/ruby/bin",
        "/usr/bin",
    ]


def test_ensure_tools_dirs_creates_expected_subdirectories(tmp_path):
    from handlers.package_env import ensure_tools_dirs

    tools_root = tmp_path / "tools"
    ensure_tools_dirs(tools_root, ("bin", "go", "gems", "pipx"))

    assert (tools_root / "bin").is_dir()
    assert (tools_root / "go").is_dir()
    assert (tools_root / "gems").is_dir()
    assert (tools_root / "pipx").is_dir()
