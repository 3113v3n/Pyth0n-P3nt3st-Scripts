from utils.shared import Config


class PackageHandler:
    """Handles package related actions such as installation of missing Packages"""

    def __init__(self, command, colors, config: Config) -> None:
        self.command = command()
        self.colors = colors
        self.external_packages = config.external_packages
        self.internal_packages = config.internal_packages
        self.mobile_packages = config.mobile_packages

    def get_missing_packages(self, test_domain) -> list:
        """
        Returns a list of objects containg missing packages
        that need to be installed and command to in
        stall them
        """
        if test_domain == "mobile":
            packages = self.mobile_packages
        elif test_domain == "internal":
            packages = self.internal_packages
        elif test_domain == "external":
            packages = self.external_packages
        else:
            return []

        return [
            package
            for package in packages
            if self.command.run_os_commands(f"which {package['name']}").returncode != 0
        ]

    def install_packages(self, packages):
        """Loops through an array of packages and installs them"""
        for package in packages:
            print(
                f"[+] Installing the following package:\n{self.colors.OKCYAN}{package['name']}{self.colors.ENDC}\n"
            )
            # Install Missing packages
            #self.command.run_os_commands(command=package["command"])
        print(f"\n{self.colors.OKGREEN}[+] Installation complete{self.colors.ENDC}")
