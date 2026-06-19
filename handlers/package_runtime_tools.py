"""Runtime tool-resolution helpers extracted from PackageHandler."""

from __future__ import annotations

from pathlib import Path
from typing import Callable


def homebrew_ruby_bin_dirs(
    *,
    os_family: str,
    which_fn: Callable[..., str | None],
    execute_command: Callable[..., object],
) -> list[str]:
    if os_family != "macos":
        return []

    dirs: list[str] = []
    try:
        brew = which_fn("brew")
        if brew:
            result = execute_command([brew, "--prefix", "ruby"], timeout=5)
            if getattr(result, "returncode", 1) == 0:
                prefix = str(getattr(result, "stdout", "")).strip()
                if prefix:
                    dirs.append(str(Path(prefix) / "bin"))
    except Exception:
        pass

    dirs.extend([
        "/opt/homebrew/opt/ruby/bin",
        "/usr/local/opt/ruby/bin",
    ])
    return dirs


def preferred_gem_executable(
    *,
    os_family: str,
    search_path: str,
    configured_gem: str | None,
    ruby_bin_dirs: list[str],
    which_fn: Callable[..., str | None],
    execute_command: Callable[..., object],
    is_system_ruby_path: Callable[[str | None], bool],
) -> str | None:
    candidates: list[str] = []

    if configured_gem:
        candidates.append(configured_gem)

    if os_family == "macos":
        for bin_dir in ruby_bin_dirs:
            candidates.append(str(Path(bin_dir) / "gem"))

    resolved = which_fn("gem", path=search_path)
    if resolved:
        candidates.append(resolved)

    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os_family == "macos" and is_system_ruby_path(candidate):
            continue
        try:
            result = execute_command([candidate, "--version"], timeout=5)
        except Exception:
            continue
        if getattr(result, "returncode", 1) == 0:
            return candidate

    if os_family != "macos":
        return resolved
    return None


def pipx_command(
    *,
    search_path: str,
    sys_executable: str,
    which_fn: Callable[..., str | None],
) -> list[str]:
    resolved = which_fn("pipx", path=search_path)
    if resolved:
        return [resolved]
    return [sys_executable, "-m", "pipx"]
