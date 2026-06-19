"""Path and environment helper functions for PackageHandler."""

from __future__ import annotations

import os
from pathlib import Path


def resolve_tools_root(repo_root: str | Path, tools_dir_name: str) -> Path:
    return Path(repo_root).resolve() / tools_dir_name


def build_search_path(current_path: str, extras: list[str]) -> str:
    path_entries = str(current_path or "").split(os.pathsep)
    merged: list[str] = []
    seen: set[str] = set()
    for entry in [*path_entries, *extras]:
        cleaned = str(entry).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        merged.append(cleaned)
    return os.pathsep.join(merged)


def is_macos_system_ruby_path(path: str | None) -> bool:
    if not path:
        return False
    resolved = str(Path(path).resolve())
    return resolved.startswith("/usr/bin/") or resolved.startswith(
        "/System/Library/Frameworks/Ruby.framework/"
    )
