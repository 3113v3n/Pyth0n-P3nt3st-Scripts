"""
domain_recon.py — Subdomain enumeration via subfinder, assetfinder, findomain,
amass, and DNS resolution via dnsx.

Each external tool is wrapped as a small static method. The public
enumerate_subdomain() returns a result dict so the orchestrator can include
its artifacts in the consolidated report.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from utils.shared.validators import Validator


_VALIDATOR = Validator()
_SUPPORTED_TOOLS = ("subfinder", "assetfinder", "findomain", "amass", "dnsx")


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
    if shutil.which(command[0]) is None:
        if debug:
            print(f"[!] {tool} not installed; skipping.")
        return []
    try:
        if debug:
            print(f"\nExecuting: {' '.join(command)}")
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as error:
        print(f"[!] {tool} failed: {error}")
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

        missing = [tool for tool in _SUPPORTED_TOOLS if shutil.which(tool) is None]

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
            "missing": missing,
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
        return shell_command(["amass", "enum", "-passive", "-d", target], "amass", debug)

    @staticmethod
    def run_findomain(target: str, debug: bool) -> list[str]:
        return shell_command(["findomain", "-t", target, "-q"], "findomain", debug)

    @staticmethod
    def run_dnsx(input_file: Path, output_file: Path) -> None:
        if shutil.which("dnsx") is None:
            return
        cmd = ["dnsx", "-a", "-resp", "-silent", "-l", str(input_file)]
        try:
            with output_file.open("w", encoding="utf-8") as fh:
                subprocess.run(cmd, stdout=fh, check=True)
        except subprocess.CalledProcessError as error:
            print(f"[!] dnsx failed: {error}")


# Backwards-compatible legacy alias used previously in tests / scripts.
file_exists = _VALIDATOR.file_exists


if __name__ == "__main__":
    DomainRecon(debug=True).enumerate_subdomain(
        "example.com", Path("./output_directory/External")
    )
