"""Environment and directory helpers for PackageHandler tool installs."""

from __future__ import annotations

import os
from pathlib import Path


def prepend_paths_to_env(env: dict[str, str], paths: list[str]) -> dict[str, str]:
    updated = dict(env)
    current = updated.get("PATH", "")
    path_entries = current.split(os.pathsep) if current else []
    for bin_path in reversed(paths):
        if bin_path and bin_path not in path_entries:
            path_entries.insert(0, bin_path)
    updated["PATH"] = os.pathsep.join(path_entries)
    return updated


def ensure_tools_dirs(tools_root: Path, subdirs: tuple[str, ...]) -> None:
    for sub in subdirs:
        (tools_root / sub).mkdir(parents=True, exist_ok=True)


def build_tool_install_env(
    *,
    base_env: dict[str, str],
    tools_root: Path,
    bin_dir: Path,
    ruby_bin_dirs: list[str],
) -> dict[str, str]:
    env = dict(base_env)
    gems_dir = str(tools_root / "gems")
    env["GOBIN"] = str(bin_dir)
    env["GOPATH"] = str(tools_root / "go")
    env["GEM_HOME"] = gems_dir
    env["GEM_PATH"] = gems_dir
    env["PIPX_HOME"] = str(tools_root / "pipx")
    env["PIPX_BIN_DIR"] = str(bin_dir)
    env["PATH"] = os.pathsep.join([str(bin_dir), *ruby_bin_dirs, env.get("PATH", "")])
    return env
