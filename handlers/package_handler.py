from utils.shared import Config


class PackageHandler:
    """Handles package related actions such as installation of missing Packages"""

    def __init__(self, command, colors, config: Config) -> None:
        self.command = command()
        self.colors = colors
        self.external_packages = config.external_packages
        self.internal_packages = config.internal_packages
        self.mobile_packages = config.mobile_packages
        self.general_packages = config.general_packages

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
            if self.command.run_os_commands(f"which {name}").returncode != 0
        ]

    def install_packages(self, packages):
        """Loops through an array of packages and installs them"""
        all_installed = False
        for package in packages:

            print(
                f"[+] Installing the following package:\n{self.colors.OKCYAN}{package['name']}{self.colors.ENDC}\n"
            )
            # Install Missing packages
            #self.command.run_os_commands(command=package["command"])
            recheck_install = self.command.run_os_commands(f"which {package['name']}")
            if recheck_install.returncode != 0:
                all_installed = False
            else:
                all_installed = True
        print(f"\n{self.colors.OKGREEN}[+] Installation complete{self.colors.ENDC}")
        return all_installed
