import subprocess
import os
from _Utils.colors import bcolors


class InstallDepencies:
    def __init__(self) -> None:
        pass

    def install_packages(self, packages):
        for package in packages:
            print(
                f"[+] Installing the following package:\n{bcolors.OKCYAN}{package['name']}{bcolors.ENDC}"
            )
            run_os_commands(command=package["command"])
        print(f"\n{bcolors.OKGREEN}[+] Installation complete{bcolors.ENDC}")


def run_os_commands(command):
    """Executes shell commands"""
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
        text=True,
    )
    # if result.returncode == 0:
    #     print(result.stdout.strip())
    return result
