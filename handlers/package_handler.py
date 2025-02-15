import platform
from utils.shared import Config, Bcolors, Commands
from typing import Dict, List


class PackageHandler(Config, Bcolors, Commands):
    """Handles package related actions such as installation of missing Packages"""

    def __init__(self) -> None:
        super().__init__()
        self.operating_system = platform.system().lower()
        self.is_supported_os = None
        

    def _check_os_support(self) -> bool:
        supported = self.operating_system == "linux"
        if not supported:
            print(f"{self.WARNING}[!] Warning: Operating system {self.operating_system} "
                  f"is not supported yet.{self.ENDC}")
        return supported

    def get_missing_packages(self, test_domain) -> list[Dict[str, str]]:
        """
        Returns a list of objects containing missing packages
        that need to be installed and command to in
        stall them
        :param test_domain: Domain to check for missing packages
        :return: List of dictionaries containing package names and installation commands
        """

        # Early return for unsupported OS
        if not self.is_supported_os:
            return []

        packages = self.general_packages.copy()
        domain_packages = {
            "mobile": self.mobile_packages,
            "internal": self.internal_packages,
            "external": self.external_packages,
        }
        if test_domain not in domain_packages:
            return []
        # update packages
        packages.extend(domain_packages[test_domain])
        # Check for missing packages
        missing_packages = []
        for pkg in packages:
            for name in pkg['name']:
                if self._is_package_missing(name):
                    missing_packages.append({
                        "name": name,
                        "command": f"{pkg['command']} {name}" if pkg['command'] != "multiple" else pkg['cmd']
                    })

        return missing_packages

    def _is_package_missing(self, package_name: str) -> bool:
        """
        Checks if a package is missing
        :param package_name: Package name
        :return bool: True if the package is missing, False otherwise
        """

        if not self.is_supported_os:
            return False

        return self.run_os_commands(f"which {package_name}").returncode != 0

    def install_packages(self, packages: List[Dict[str, str]]) -> bool:
        """Loops through an array of packages and installs them
        :param packages: List of packages to install
        :return bool: True if the packages are installed, False otherwise
        """
        if not self.is_supported_os:
            return True

        if not packages:
            return True

        installed_packages = []
        for package in packages:
            try:
                print(
                    f"[+] Installing the following package:\n{self.OKCYAN}{package['name']}{self.ENDC}\n"
                )
                # Install Missing packages
                install_status = self.run_os_commands(command=package["command"])
                if install_status.returncode != 0:
                    print(f"{self.FAIL}[!] Installation of {package['name']} failed.{self.ENDC}")
                    continue

                # Verify Installation
                if self._verify_installation(package['name']):
                    installed_packages.append(package['name'])
                    print(f"{self.OKGREEN} [+] Successfully installed {package['name']}{self.ENDC}")
                else:
                    print(f"{self.FAIL}[!] Installation verification of {package['name']} failed.{self.ENDC}")
            except Exception as error:
                print(f"{self.WARNING}[!] Error Installing {package['name']}: {str(error)}{self.ENDC}")
                continue

        if installed_packages:
            print(f"\n{self.OKGREEN}[+] Successfully installed {len(installed_packages)}"
                  f" packages.{self.ENDC} ")
        return len(installed_packages) == len(packages)

    def _verify_installation(self, package_name: str) -> bool:
        """
        Verify package installation
        :param package_name: Package name
        :return bool: True if the package is installed, False otherwise
        """

        if not self.is_supported_os:
            return True
        return self.run_os_commands(f"which {package_name}").returncode == 0

    def _install_windows_package(self, package: List[Dict[str, str]]) -> bool:
        """Install Windows packages"""
        raise NotImplementedError("Windows packages not supported yet.")

    def _install_macos_package(self, package: List[Dict[str, str]]) -> bool:
        """Install MacOS packages"""
        raise NotImplementedError("MacOS packages not supported yet.")
