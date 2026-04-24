"""
package_handler.py — Manages installation of external tools required by each assessment module.

Security: Package presence checks now use shutil.which() instead of a shell
`which <name>` command, eliminating the shell-injection risk that existed when
package names were interpolated into a shell string.
"""

import re
import shutil
import platform
from importlib import metadata
from handlers.messages import DisplayHandler
from utils.shared import Config, Commands
from typing import Dict, List

# [Security] Only allow package names that consist of alphanumeric chars,
# hyphens, dots and underscores — no shell metacharacters.
_SAFE_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class PackageHandler(Config, DisplayHandler, Commands):
    """Manages checking and installing packages required by the pentest modules."""

    def __init__(self) -> None:
        super().__init__()
        self.operating_system = platform.system().lower()
        self.is_supported_os = None

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.operating_system = platform.system().lower()
        self.is_supported_os = None

    # Backward-compatible alias kept so existing call sites work.
    @classmethod
    def reset_class_states(cls):
        """Deprecated — use reset_state() on the instance instead."""
        cls.operating_system = platform.system().lower()
        cls.is_supported_os = None

    @staticmethod
    def _is_pip_package_missing(package_name: str) -> bool:
        """Return True when *package_name* is missing in the current Python env.

        Uses importlib.metadata against the active interpreter so checks resolve
        packages installed in the currently active virtualenv.
        """
        try:
            metadata.version(package_name)
            return False
        except metadata.PackageNotFoundError:
            return True
        except Exception:
            # Fallback to "missing" if metadata query fails unexpectedly.
            return True

    def _check_is_supported(self) -> bool:
        """Return True if the current OS supports automatic package installation.

        Returns:
            True only on Linux systems.
        """
        supported = self.operating_system == "linux"
        if not supported:
            self.print_warning_message(
                f"Operating system '{self.operating_system}' does not support "
                "automatic package installation. Install required tools manually."
            )
        return supported

    def get_missing_packages(self, test_domain: str) -> list[Dict[str, str]]:
        """Return a list of packages required by *test_domain* that are not installed.

        Args:
            test_domain: One of "mobile", "internal", or "external".

        Returns:
            List of dicts with "name" and "command" keys for each missing package.
        """
        if not self.is_supported_os:
            return []

        domain_packages = {
            "mobile": self.mobile_packages,
            "internal": self.internal_packages,
            "external": self.external_packages,
        }
        if test_domain not in domain_packages:
            return []

        module_packages = list(domain_packages[test_domain])

        # Add shared bootstrap packages only when the selected module needs them.
        requires_pipx = any(
            str(pkg.get("command", "")).strip().startswith("pipx")
            for pkg in module_packages
        )
        packages = []
        if requires_pipx:
            packages.extend(self.general_packages)
        packages.extend(module_packages)

        missing_packages = []
        for pkg in packages:
            names = pkg.get("name", [])
            missing_names = [name for name in names if self._is_package_missing(name)]
            if not missing_names:
                continue

            # Run grouped installation commands only once.
            if pkg.get("command") == "multiple":
                install_cmd = pkg.get("cmd")
                if not install_cmd:
                    self.print_error_message(
                        f"Invalid package config for {missing_names}: missing 'cmd' value."
                    )
                    continue
                missing_packages.append(
                    {
                        "name": ", ".join(missing_names),
                        "command": install_cmd,
                        "verify_names": missing_names,
                    }
                )
                continue

            # Optional explicit command for non-multiple entries.
            if pkg.get("cmd"):
                missing_packages.append(
                    {
                        "name": ", ".join(missing_names),
                        "command": pkg["cmd"],
                        "verify_names": missing_names,
                    }
                )
                continue

            for name in missing_names:
                install_cmd = f"{pkg['command']} {name}"
                missing_packages.append(
                    {
                        "name": name,
                        "command": install_cmd,
                        "verify_names": [name],
                    }
                )

        return missing_packages

    def _is_package_missing(self, package_name: str) -> bool:
        """Return True if *package_name* is not installed.

        CLI tools are checked via shutil.which(); Python SDK dependencies such
        as anthropic are checked via importlib.metadata in the active venv.

        Args:
            package_name: Dependency name to check, e.g. "nmap" or "anthropic".

        Returns:
            True if the dependency is missing.
        """
        if not self.is_supported_os:
            return False

        # Python SDK dependencies are checked against pip packages in the active venv.
        if package_name == "anthropic":
            return self._is_pip_package_missing("anthropic")

        # [Security] shutil.which() never spawns a shell — no injection possible.
        return shutil.which(package_name) is None

    def install_packages(self, packages: List[Dict[str, str]]) -> bool:
        """Install a list of missing packages.

        Args:
            packages: List returned by get_missing_packages().

        Returns:
            True if all packages were installed successfully.
        """
        if not self.is_supported_os or not packages:
            return True

        installed_packages = set()
        all_success = True
        for package in packages:
            package_name = package["name"]
            verify_names = package.get("verify_names") or [package_name]

            # [Security] Validate each package/binary token before using a shell command.
            unsafe_names = [name for name in verify_names if not _SAFE_PACKAGE_NAME.match(name)]
            if unsafe_names:
                self.print_error_message(
                    f"Skipping package with unsafe name(s): {unsafe_names}"
                )
                all_success = False
                continue

            try:
                self.print_info_message(f"Installing package: {package_name}")
                install_status = self.run_os_commands(command=package["command"])
                if install_status.returncode != 0:
                    stderr = (install_status.stderr or "").strip()
                    stdout = (install_status.stdout or "").strip()
                    details = stderr or stdout or f"exit code {install_status.returncode}"
                    self.print_error_message(
                        message=f"Installation of {package_name} failed.",
                        exception_error=details,
                    )
                    all_success = False
                    continue

                if all(self._verify_installation(name) for name in verify_names):
                    installed_packages.update(verify_names)
                    self.print_success_message(f"Successfully installed {package_name}")
                else:
                    self.print_error_message(
                        message=f"Installation of {package_name} failed.",
                        exception_error=(
                            f"Verification failed for binaries: {', '.join(verify_names)}. "
                            f"Command was: {package['command']}"
                        ),
                    )
                    all_success = False

            except Exception as error:
                self.print_error_message(
                    message=f"Installation of {package_name} failed.",
                    exception_error=error,
                )
                all_success = False

        if installed_packages:
            self.print_success_message(
                f"Successfully installed {len(installed_packages)} package(s)."
            )
        return all_success

    def _verify_installation(self, package_name: str) -> bool:
        """Return True if *package_name* is now installed.

        Uses importlib.metadata for anthropic and shutil.which() for binaries.

        Args:
            package_name: Tool name to verify.

        Returns:
            True if the tool was found.
        """
        if not self.is_supported_os:
            return True
        if package_name == "anthropic":
            return not self._is_pip_package_missing("anthropic")
        # [Security] shutil.which() replaces shell `which <name>`.
        return shutil.which(package_name) is not None

    def _install_windows_package(self, package: List[Dict[str, str]]) -> bool:
        """Placeholder for Windows package installation (not yet implemented)."""
        raise NotImplementedError("Windows package installation is not supported yet.")

    def _install_macos_package(self, package: List[Dict[str, str]]) -> bool:
        """Placeholder for macOS package installation (not yet implemented)."""
        raise NotImplementedError("macOS package installation is not supported yet.")
