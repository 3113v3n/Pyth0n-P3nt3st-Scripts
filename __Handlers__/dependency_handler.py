class InstallDepencies:
    def __init__(self, os_commands, colors) -> None:
        self.command = os_commands
        self.colors = colors

    def install_packages(self, packages):
        for package in packages:
            print(
                f"[+] Installing the following package:\n{self.colors.OKCYAN}{package['name']}{self.colors.ENDC}\n"
            )
            # self.command.run_os_commands(command=package["command"])
        print(f"\n{self.colors.OKGREEN}[+] Installation complete{self.colors.ENDC}")
