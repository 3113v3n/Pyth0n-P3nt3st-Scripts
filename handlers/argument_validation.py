"""Pure helpers for normalizing and validating CLI module arguments."""

from __future__ import annotations

from pathlib import Path

from utils.shared.errors import MissingRequiredFileError, ModuleArgumentError


def require_regular_file(path: str, label: str) -> Path:
    """Return the validated path when *path* points to a regular file."""
    candidate = Path(path)
    if candidate.is_file():
        return candidate
    if candidate.is_dir():
        raise MissingRequiredFileError(f"{label} must be a file, not a directory: {path}")
    raise MissingRequiredFileError(f"{label} file does not exist: {path}")


def normalize_domain(raw_domain: str) -> str:
    """Strip URL scheme/trailing slash from a user-provided domain argument."""
    return str(raw_domain).replace("https://", "").replace("http://", "").strip("/")


def parse_phase_selection(
    raw_phases: str | None,
    default_phases: tuple[str, ...],
    valid_phases: tuple[str, ...],
) -> tuple[str, ...]:
    """Normalize comma-separated phase text into an ordered, de-duplicated tuple."""
    requested = tuple(
        dict.fromkeys(
            phase.strip().lower()
            for phase in (raw_phases or "").split(",")
            if phase.strip()
        )
    ) or tuple(default_phases)
    unknown = [phase for phase in requested if phase not in valid_phases]
    if unknown:
        raise ModuleArgumentError(
            f"Unknown phase(s): {unknown}. Valid phases: {', '.join(valid_phases)}"
        )
    return requested


def resolve_safe_operator_tag(
    safe_mode: bool,
    operator_tag: str | None,
    default_tag: str,
) -> str:
    """Return the normalized operator tag for external safe-mode runs."""
    normalized = str(operator_tag or "").strip()
    if safe_mode and not normalized:
        return default_tag
    return normalized
