from utils.shared import Config, Bcolors, Commands


class PackageHandler(Config, Bcolors, Commands):
    """Handles package related actions such as installation of missing Packages"""

    def __init__(self) -> None:
        super().__init__()
        pass

    def get_missing_packages(self, test_domain) -> list:
        """
        Returns a list of objects containing missing packages
        that need to be installed and command to in
        stall them
        """

        packages = self.general_packages
        if test_domain == "mobile":
            to_install = self.mobile_packages
        elif test_domain == "internal":
            to_install = self.internal_packages
        elif test_domain == "external":
            to_install = self.external_packages
        else:
            return []

        for package in to_install:
            packages.append(package)

        return [
            {"name": name, "command": f"{pkg['command']} {name}" if pkg['command'] != "multiple" else pkg['cmd']}
            for pkg in packages
            for name in pkg['name']
            if self.run_os_commands(f"which {name}").returncode != 0
        ]

    def install_packages(self, packages):
        """Loops through an array of packages and installs them"""
        all_installed = False
        for package in packages:

            print(
                f"[+] Installing the following package:\n{self.OKCYAN}{package['name']}{self.ENDC}\n"
            )
            # Install Missing packages
            self.run_os_commands(command=package["command"])
            recheck_install = self.run_os_commands(f"which {package['name']}")
            if recheck_install.returncode != 0:
                all_installed = False
            else:
                all_installed = True
        print(f"\n{self.OKGREEN}[+] Installation complete{self.ENDC}")
        return all_installed
