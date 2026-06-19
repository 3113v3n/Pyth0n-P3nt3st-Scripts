import os


def test_resolve_tools_root_uses_repo_root(tmp_path):
    from handlers.package_paths import resolve_tools_root

    assert resolve_tools_root(tmp_path, "tools") == tmp_path / "tools"


def test_build_search_path_deduplicates_and_preserves_order(tmp_path):
    from handlers.package_paths import build_search_path

    py_bin = tmp_path / "venv/bin"
    tools_bin = tmp_path / "tools/bin"
    merged = build_search_path(
        current_path=os.pathsep.join(["/usr/bin", str(py_bin), "/usr/bin"]),
        extras=[str(py_bin), str(tools_bin), "", "/opt/local/bin"],
    )

    assert merged.split(os.pathsep) == [
        "/usr/bin",
        str(py_bin),
        str(tools_bin),
        "/opt/local/bin",
    ]


def test_is_macos_system_ruby_path_detects_system_locations(tmp_path):
    from handlers.package_paths import is_macos_system_ruby_path

    assert is_macos_system_ruby_path("/usr/bin/gem") is True
    assert (
        is_macos_system_ruby_path(
            "/System/Library/Frameworks/Ruby.framework/Versions/2.6/usr/bin/gem"
        )
        is True
    )
    assert is_macos_system_ruby_path(str(tmp_path / "custom/bin/gem")) is False
