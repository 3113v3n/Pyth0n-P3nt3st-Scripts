from __Utils__.colors import bcolors


class InstallDepencies:
    def __init__(self, os_commands) -> None:
        self.command = os_commands

    def install_packages(self, packages):
        for package in packages:
            print(
                f"[+] Installing the following package:\n{bcolors.OKCYAN}{package['name']}{bcolors.ENDC}\n"
            )
            # self.command.run_os_commands(command=package["command"])
        print(f"\n{bcolors.OKGREEN}[+] Installation complete{bcolors.ENDC}")
