"""Core lifecycle helpers for PentestFramework."""

from __future__ import annotations

import sys

from utils.shared.ai_assistant import PentestAI
from utils.shared.colors import Bcolors


class FrameworkCoreMixin:
    """Initialization, dependency checks, and domain loading helpers."""

    def initialize_classes(self) -> dict:
        """Initialize core classes required for startup and shared flows."""
        try:
            from handlers.helper_handler import HelpHandler
            from handlers.network_handler import NetworkHandler
            from handlers.package_handler import PackageHandler
            from handlers.user_handler import UserHandler
            from utils.shared.commands import Commands

            network_instance = NetworkHandler()
            helper_instance = HelpHandler()
            command_instance = Commands()

            return {
                "package": PackageHandler(),
                "command": command_instance,
                "network": network_instance,
                "user": UserHandler(helper_instance, command_instance),
                "helper": helper_instance,
                "domains": {},
            }
        except ModuleNotFoundError as error:
            self.print_error_message(
                message="Missing core dependency", exception_error=error
            )
            sys.exit(1)
        except Exception as error:
            self.print_error_message(
                message="Error initializing classes", exception_error=error
            )
            sys.exit(1)

    def _load_domain(self, domain_key: str):
        """Lazily initialize and cache a domain handler."""
        domain_cache = self.classes.setdefault("domains", {})
        if domain_key in domain_cache:
            return domain_cache[domain_key]

        try:
            if domain_key == "vulnerability":
                from domains.vulnerability_module import VulnerabilityAnalysis

                domain_obj = VulnerabilityAnalysis()
            elif domain_key == "mobile":
                from domains.mobile_module import MobileAssessment

                domain_obj = MobileAssessment()
            elif domain_key == "password":
                from domains.password_module import PasswordModule

                domain_obj = PasswordModule()
            elif domain_key == "internal":
                from domains.internal_module import InternalAssessment

                domain_obj = InternalAssessment(
                    self.classes["network"],
                    self.classes["helper"],
                )
            else:
                return None
        except ModuleNotFoundError as error:
            self.print_error_message(
                message=f"Missing Python dependency for '{domain_key}' module",
                exception_error=(
                    f"{error.name}. Install dependencies with "
                    "'pip install -r requirements.txt'"
                ),
            )
            return None
        except Exception as error:
            self.print_error_message(
                message=f"Error initializing '{domain_key}' module",
                exception_error=error,
            )
            return None

        domain_obj.ai = self.ai
        domain_cache[domain_key] = domain_obj
        return domain_obj

    def _attach_ai_to_domains(self) -> None:
        """Attach current AI instance to all loaded domain handlers."""
        domain_cache = self.classes.get("domains", {})
        for domain_obj in domain_cache.values():
            domain_obj.ai = self.ai

    def ensure_ai_ready(self) -> None:
        """Initialize AI once, only after dependency checks for selected module."""
        if not self.use_ai:
            self.ai = None
            self._attach_ai_to_domains()
            return

        if self.ai is None:
            self.ai = PentestAI()
        self._attach_ai_to_domains()

    def check_packages(self, user_test_domain: str) -> bool:
        """Check and install required packages for the selected domain."""
        _package = self.classes["package"]
        package_supported_domains = {"mobile", "internal", "external"}

        if user_test_domain not in package_supported_domains:
            return True

        print(Bcolors.WARNING + "[?] Checking for required packages..." + Bcolors.ENDC)
        if _package.is_supported_os is None:
            _package.is_supported_os = _package._check_is_supported()
            self.os = _package.operating_system

        if not _package.is_supported_os:
            self.print_info_message("Skipping package installation on unsupported OS")
            return True

        missing_packages = _package.get_missing_packages(user_test_domain)
        if not missing_packages:
            return True

        num_of_packages = len(missing_packages)
        self.print_warning_message(
            f"Missing Packages Kindly be patient as we install {num_of_packages} package(s).."
        )
        try:
            return _package.install_packages(missing_packages)
        except RuntimeError as error:
            self.print_error_message(
                message="Failed to install some packages",
                exception_error=error,
            )
            return False

    def reset_class_states(self):
        """Reset the states of all classes."""
        try:
            self.classes = self.initialize_classes()
            if self.classes["network"]:
                self.classes["network"].reset_class_states()
            if self.classes["package"]:
                self.classes["package"].reset_class_states()
            if self.classes["user"]:
                self.classes["user"].reset_class_states()
            self.classes["domains"] = {}
        except Exception as error:
            self.print_error_message(
                message="Error resetting class states",
                exception_error=error,
            )
