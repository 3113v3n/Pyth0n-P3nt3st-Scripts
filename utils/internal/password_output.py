"""Output and parsing helpers for password module operations."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4
from .password_constants import PASSWORD_OUTPUT_EXTENSION

COMMON_PASSWORD_HEADER = "----------------- Common Password ---------------------------------"
COMMON_PASSWORD_FOOTER = "------------------------------------------------------------------"


def build_password_output_path(
    save_dir: str,
    output_basename: str,
    name_generator: callable,
) -> str:
    """Build a generated output path in *save_dir* using the framework naming helper."""
    try:
        generated_name = name_generator(
            output_basename,
            extension=PASSWORD_OUTPUT_EXTENSION,
        )
    except TypeError:
        generated_name = name_generator(output_basename)

    candidate = Path(save_dir) / generated_name
    if candidate.exists():
        candidate = candidate.with_name(
            f"{candidate.stem}_{uuid4().hex[:8]}{candidate.suffix}"
        )
    return str(candidate)


def build_grouped_password_output(user_password_pairs: list[tuple[str, str]]) -> str:
    """Render credentials using grouped common-password blocks and one-line uniques.

    Grouped format example:
        ----------------- Common Password ---------------------------------
        PASSWORD: Passw0rd123
        COUNT: 2
        USERS:
            - user1
            - user2
        ------------------------------------------------------------------

    Unique credentials remain as:
        username:password
    """
    if not user_password_pairs:
        return ""

    password_to_users: dict[str, list[str]] = {}
    for username, password in user_password_pairs:
        password_to_users.setdefault(password, []).append(username)

    lines: list[str] = []

    # Write grouped blocks first (passwords reused by 2+ users).
    for password, users in password_to_users.items():
        if len(users) <= 1:
            continue
        lines.extend(
            [
                COMMON_PASSWORD_HEADER,
                f"PASSWORD: {password}",
                f"COUNT: {len(users)}",
                "USERS:",
            ]
        )
        lines.extend([f"    - {username}" for username in users])
        lines.extend(["", COMMON_PASSWORD_FOOTER, ""])

    # Keep unique credentials as username:password one-liners.
    for password, users in password_to_users.items():
        if len(users) == 1:
            lines.append(f"{users[0]}:{password}")

    if not lines:
        return ""
    return "\n".join(lines).rstrip() + "\n"


def parse_credentials_from_output(filepath: str) -> dict[str, str]:
    """Parse mixed credential output file into a ``{username: password}`` mapping.

    Supports:
      1. ``username:password`` lines
      2. grouped common-password blocks (COMMON_PASSWORD_HEADER/FOOTER)
    """
    user_pass: dict[str, str] = {}
    if not filepath:
        return user_pass

    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle]
    except OSError:
        return user_pass

    idx = 0
    total = len(lines)
    while idx < total:
        raw_line = lines[idx]
        stripped = raw_line.strip()

        if not stripped:
            idx += 1
            continue

        if stripped == COMMON_PASSWORD_HEADER:
            idx += 1
            password = ""
            users: list[str] = []

            while idx < total and lines[idx].strip() != COMMON_PASSWORD_FOOTER:
                block_line = lines[idx].strip()
                if block_line.startswith("PASSWORD:"):
                    password = block_line.split(":", 1)[1].strip()
                elif block_line.startswith("- "):
                    username = block_line[2:].strip()
                    if username:
                        users.append(username)
                idx += 1

            if password and users:
                for username in users:
                    user_pass[username] = password

            if idx < total and lines[idx].strip() == COMMON_PASSWORD_FOOTER:
                idx += 1
            continue

        if ":" in stripped and not (
            stripped.startswith("PASSWORD:") or stripped.startswith("COUNT:")
        ):
            username, password = stripped.split(":", 1)
            username = username.strip()
            password = password.strip()
            if username:
                user_pass[username] = password

        idx += 1

    return user_pass


def read_passwords_from_output(filepath: str) -> list[str]:
    """Read plaintext passwords from mixed-format password output file.

    For grouped common-password blocks, the password is repeated for each listed
    user to preserve frequency semantics used by downstream AI analysis.
    """
    passwords: list[str] = []
    if not filepath:
        return passwords
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle]
    except OSError:
        return passwords

    idx = 0
    total = len(lines)
    while idx < total:
        stripped = lines[idx].strip()
        if not stripped:
            idx += 1
            continue

        if stripped == COMMON_PASSWORD_HEADER:
            idx += 1
            password = ""
            user_count = 0

            while idx < total and lines[idx].strip() != COMMON_PASSWORD_FOOTER:
                block_line = lines[idx].strip()
                if block_line.startswith("PASSWORD:"):
                    password = block_line.split(":", 1)[1].strip()
                elif block_line.startswith("- "):
                    user_count += 1
                idx += 1

            if password and user_count > 0:
                passwords.extend([password] * user_count)

            if idx < total and lines[idx].strip() == COMMON_PASSWORD_FOOTER:
                idx += 1
            continue

        if ":" in stripped and not (
            stripped.startswith("PASSWORD:") or stripped.startswith("COUNT:")
        ):
            _, password = stripped.split(":", 1)
            passwords.append(password.strip())

        idx += 1

    return passwords
