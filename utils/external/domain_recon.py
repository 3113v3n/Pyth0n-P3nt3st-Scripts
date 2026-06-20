"""
domain_recon.py — Subdomain enumeration via subfinder, assetfinder, findomain,
amass, and DNS resolution via dnsx.

Each external tool is wrapped as a small static method. The public
enumerate_subdomain() returns a result dict so the orchestrator can include
its artifacts in the consolidated report.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from handlers.messages import DisplayHandler
from utils.shared.commands import Commands
from utils.shared.validators import Validator
from .tooling import available_name, which_tool


_VALIDATOR = Validator()
_SUPPORTED_TOOLS = ("subfinder", "assetfinder", "findomain", "amass", "dnsx")
_COMMANDS = Commands()
_AMASS_NATIVE_BIN = Path("/usr/lib/amass/amass")
_LIBPOSTAL_SHARE_DIR = Path("/usr/share/libpostal")
_LIBPOSTAL_VAR_DIR = Path("/var/lib/libpostal")


def _emit_message(message: str) -> None:
    DisplayHandler._emit_message(message)


def _resolve_amass_executable() -> str | None:
    """Prefer the real amass binary over wrapper scripts when available."""
    if _AMASS_NATIVE_BIN.exists() and os.access(_AMASS_NATIVE_BIN, os.X_OK):
        return str(_AMASS_NATIVE_BIN)
    return which_tool("amass")


def _amass_libpostal_fix_message() -> str:
    """Return actionable remediation for libpostal data-dir mismatches."""
    has_var_data = (_LIBPOSTAL_VAR_DIR / "transliteration").exists()
    if has_var_data:
        return (
            "[!] amass preflight failed: libpostal data found in /var/lib/libpostal "
            "but missing in /usr/share/libpostal.\n"
            "[!] Fix: sudo mkdir -p /usr/share/libpostal && "
            "sudo cp -a /var/lib/libpostal/. /usr/share/libpostal/"
        )
    return (
        "[!] amass preflight failed: libpostal data missing in /usr/share/libpostal.\n"
        "[!] Fix: sudo libpostal_data download all /usr/share/libpostal"
    )


def _amass_preflight(executable: str) -> bool:
    """Validate amass runtime prerequisites before long-running enumeration."""
    try:
        resolved = Path(executable).resolve()
    except OSError:
        return False

    # Debian/Kali amass builds can link libpostal with hard-coded
    # /usr/share/libpostal paths; fail early with a clear fix message.
    if resolved == _AMASS_NATIVE_BIN and not (_LIBPOSTAL_SHARE_DIR / "transliteration").exists():
        _emit_message(_amass_libpostal_fix_message())
        return False
    return True


def _tool_available(tool: str) -> bool:
    """Tool availability with amass-specific resolver."""
    if tool == "amass":
        return _resolve_amass_executable() is not None
    return which_tool(tool) is not None


def is_valid_subdomain(subdomain: str, root_domain: str) -> bool:
    """Return True if *subdomain* is a host under *root_domain*."""
    pattern = rf"^(?:[\w-]+\.)+{re.escape(root_domain)}$"
    return re.match(pattern, subdomain.strip()) is not None


def filter_subdomain(subdomains, root_domain: str) -> set[str]:
    """Filter a sequence of strings to those that look like valid subdomains."""
    return {sub.strip() for sub in subdomains if is_valid_subdomain(sub, root_domain)}


def shell_command(command: list[str], tool: str, debug: bool = False) -> list[str]:
    """Run *command* and return its stdout split into lines.

    Returns an empty list when the binary is missing or the command fails so
    downstream callers can keep operating on whatever results exist.
    """
    raw_executable = str(command[0]).strip()
    if "/" in raw_executable:
        path = Path(raw_executable)
        executable = str(path) if path.exists() and os.access(path, os.X_OK) else None
    else:
        executable = which_tool(raw_executable)
    if executable is None:
        if debug:
            _emit_message(f"[!] {tool} not installed; skipping.")
        return []
    command = [executable, *command[1:]]
    try:
        if debug:
            _emit_message(f"\nExecuting: {' '.join(command)}")
        result = _COMMANDS.stream_command(command, prefix=f"[{tool}] ")
        if result.returncode != 0:
            if tool == "amass":
                output = str(result.stdout)
                if "Error loading transliteration module" in output or "libpostal_setup_datadir" in output:
                    _emit_message(_amass_libpostal_fix_message())
            _emit_message(f"[!] {tool} failed with exit code {result.returncode}")
            return []
        return result.stdout.splitlines()
    except OSError as error:
        _emit_message(f"[!] {tool} failed: {error}")
        return []


class DomainRecon:
    """Coordinate subdomain enumeration and DNS resolution for a target domain."""

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug

    def enumerate_subdomain(self, domain: str, output_dir: Path) -> dict:
        """Enumerate subdomains for *domain* and resolve them via dnsx.

        Args:
            domain:     Target domain. URL prefixes (http/https) are stripped.
            output_dir: Directory where subdomain files are written.

        Returns:
            Dict with keys:
                subdomains_file:  Path to all-discovered subdomains.
                resolved_file:    Path to dnsx-resolved subdomains.
                subdomain_count:  Total unique subdomains discovered.
                resolved_count:   Resolved subdomain count.
                missing:          List of tools that were unavailable.
        """
        formatted_domain = self._format_domain(domain)
        output_dir.mkdir(parents=True, exist_ok=True)

        subdomain_file = output_dir / f"{formatted_domain}_subdomains.txt"
        resolved_file = output_dir / f"resolved_{formatted_domain}_subdomains.txt"

        missing = [tool for tool in _SUPPORTED_TOOLS if not _tool_available(tool)]

        if not _VALIDATOR.file_exists(str(subdomain_file)):
            collected = (
                self.run_subfinder(formatted_domain, self.debug)
                + self.run_assetfinder(formatted_domain, self.debug)
                + self.run_findomain(formatted_domain, self.debug)
                + self.run_amass(formatted_domain, self.debug)
            )
            unique_subs = filter_subdomain(collected, formatted_domain)
            if unique_subs:
                subdomain_file.write_text(
                    "\n".join(sorted(unique_subs)) + "\n",
                    encoding="utf-8",
                )

        subdomain_count = self._line_count(subdomain_file)
        if subdomain_count and not _VALIDATOR.file_exists(str(resolved_file)):
            self.run_dnsx(subdomain_file, resolved_file)

        resolved_count = self._line_count(resolved_file)
        return {
            "subdomains_file": subdomain_file if subdomain_file.exists() else None,
            "resolved_file": resolved_file if resolved_file.exists() else None,
            "subdomain_count": subdomain_count,
            "resolved_count": resolved_count,
            "missing_optional": missing,
        }

    @staticmethod
    def _format_domain(domain: str) -> str:
        return domain.replace("https://", "").replace("http://", "").strip("/")

    @staticmethod
    def _line_count(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            return sum(
                1
                for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            )
        except OSError:
            return 0

    # ------------------------------------------------------------------
    # Tool wrappers
    # ------------------------------------------------------------------

    @staticmethod
    def run_subfinder(target: str, debug: bool) -> list[str]:
        return shell_command(["subfinder", "-d", target, "-all", "-recursive", "-silent"], "subfinder", debug)

    @staticmethod
    def run_assetfinder(target: str, debug: bool) -> list[str]:
        return shell_command(["assetfinder", "--subs-only", target], "assetfinder", debug)

    @staticmethod
    def run_amass(target: str, debug: bool) -> list[str]:
        executable = _resolve_amass_executable()
        if executable is None:
            if debug:
                _emit_message("[!] amass not installed; skipping.")
            return []
        if not _amass_preflight(executable):
            return []
        return shell_command([executable, "enum", "-passive", "-d", target], "amass", debug)

    @staticmethod
    def run_findomain(target: str, debug: bool) -> list[str]:
        return shell_command(["findomain", "-t", target, "-q"], "findomain", debug)

    @staticmethod
    def run_dnsx(input_file: Path, output_file: Path) -> None:
        dnsx = available_name("dnsx")
        if dnsx is None:
            return
        cmd = [dnsx, "-a", "-resp", "-silent", "-l", str(input_file)]
        result = _COMMANDS.stream_command(cmd, output_file=output_file, prefix="[dnsx] ")
        if result.returncode != 0:
            output_file.unlink(missing_ok=True)
            _emit_message(f"[!] dnsx failed with exit code {result.returncode}")


# Backwards-compatible legacy alias used previously in tests / scripts.
file_exists = _VALIDATOR.file_exists


if __name__ == "__main__":
    DomainRecon(debug=True).enumerate_subdomain(
        "example.com", Path("./output_directory/External")
    )
