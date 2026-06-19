"""Helpers for project-local virtualenv bootstrap and requirements stamping."""

from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BootstrapPaths:
    root: Path
    venv_dir: Path
    venv_python: Path
    requirements_file: Path


def resolve_bootstrap_paths(
    *,
    project_root: str | Path,
    venv_name: str,
    requirements_file: str,
    os_name: str = os.name,
) -> BootstrapPaths:
    root = Path(project_root).resolve()
    python_name = "Scripts/python.exe" if os_name == "nt" else "bin/python"
    venv_dir = root / venv_name
    return BootstrapPaths(
        root=root,
        venv_dir=venv_dir,
        venv_python=venv_dir / python_name,
        requirements_file=root / requirements_file,
    )


def is_running_in_project_venv(current_prefix: str | Path, venv_dir: str | Path) -> bool:
    try:
        prefix_path = Path(current_prefix).resolve()
        venv_path = Path(venv_dir).resolve()
    except OSError:
        return False
    return prefix_path == venv_path or venv_path in prefix_path.parents


def requirements_hash(requirements_file: Path) -> str:
    return hashlib.sha256(requirements_file.read_bytes()).hexdigest()


def requirements_stamp_path(venv_dir: Path, stamp_filename: str) -> Path:
    return venv_dir / stamp_filename


def requirements_stamp_matches(
    venv_dir: Path,
    requirements_file: Path,
    stamp_filename: str = ".requirements.sha256",
) -> bool:
    if not requirements_file.exists():
        return True
    stamp_file = requirements_stamp_path(venv_dir, stamp_filename)
    if not stamp_file.exists():
        return False
    try:
        recorded_hash = stamp_file.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return recorded_hash == requirements_hash(requirements_file)


def write_requirements_stamp(
    venv_dir: Path,
    requirements_file: Path,
    stamp_filename: str = ".requirements.sha256",
) -> None:
    stamp_file = requirements_stamp_path(venv_dir, stamp_filename)
    stamp_file.write_text(f"{requirements_hash(requirements_file)}\n", encoding="utf-8")


def install_requirements_into_venv(
    venv_python: Path,
    requirements_file: Path,
    venv_dir: Path,
    stamp_filename: str = ".requirements.sha256",
) -> None:
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-r", str(requirements_file)],
        check=True,
    )
    write_requirements_stamp(venv_dir, requirements_file, stamp_filename)
