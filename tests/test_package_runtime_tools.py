def test_homebrew_ruby_bin_dirs_returns_empty_outside_macos():
    from handlers.package_runtime_tools import homebrew_ruby_bin_dirs

    result = homebrew_ruby_bin_dirs(
        os_family="debian",
        which_fn=lambda command: None,
        execute_command=lambda command, timeout: None,
    )

    assert result == []


def test_homebrew_ruby_bin_dirs_uses_brew_prefix_and_default_paths():
    from handlers.package_runtime_tools import homebrew_ruby_bin_dirs

    class Result:
        returncode = 0
        stdout = "/custom/ruby\n"

    result = homebrew_ruby_bin_dirs(
        os_family="macos",
        which_fn=lambda command: "/opt/homebrew/bin/brew" if command == "brew" else None,
        execute_command=lambda command, timeout: Result(),
    )

    assert result == [
        "/custom/ruby/bin",
        "/opt/homebrew/opt/ruby/bin",
        "/usr/local/opt/ruby/bin",
    ]


def test_preferred_gem_executable_skips_system_ruby_on_macos():
    from handlers.package_runtime_tools import preferred_gem_executable

    responses = {
        "/usr/bin/gem": 0,
        "/opt/homebrew/opt/ruby/bin/gem": 0,
    }

    def execute_command(command, timeout):
        class Result:
            returncode = responses.get(command[0], 1)

        return Result()

    result = preferred_gem_executable(
        os_family="macos",
        search_path="/usr/bin:/opt/homebrew/opt/ruby/bin",
        configured_gem=None,
        ruby_bin_dirs=["/opt/homebrew/opt/ruby/bin"],
        which_fn=lambda name, path=None: "/usr/bin/gem" if name == "gem" else None,
        execute_command=execute_command,
        is_system_ruby_path=lambda path: path.startswith("/usr/bin/"),
    )

    assert result == "/opt/homebrew/opt/ruby/bin/gem"


def test_pipx_command_prefers_resolved_binary_and_falls_back_to_module():
    from handlers.package_runtime_tools import pipx_command

    resolved = pipx_command(
        search_path="/custom/bin",
        sys_executable="/usr/bin/python3",
        which_fn=lambda name, path=None: "/custom/bin/pipx" if name == "pipx" else None,
    )
    fallback = pipx_command(
        search_path="/custom/bin",
        sys_executable="/usr/bin/python3",
        which_fn=lambda name, path=None: None,
    )

    assert resolved == ["/custom/bin/pipx"]
    assert fallback == ["/usr/bin/python3", "-m", "pipx"]
