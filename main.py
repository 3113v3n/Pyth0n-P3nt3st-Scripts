from pprint import pprint
from __Utils__.colors import bcolors
from __Utils__.commands import Commands
from __Utils__.validators import Validators
from __Utils__.locate_dependencies import LocateDependencies
from __Handlers__.install_dependencies import InstallDepencies

command = Commands()
dependencies = LocateDependencies(command)
install_package = InstallDepencies(command)
validator_checks = Validators()


def check_for_dependencies():
    # check if package list contains any packages
    if len(dependencies.to_install) == 0:
        print(f"{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        ready_to_start = True
    else:
        ready_to_start = False
        print(
            f"{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {len(dependencies.to_install)} package(s)..{bcolors.ENDC}"
        )
        install_package.install_packages(dependencies.to_install)
    ready_to_start = True
    return ready_to_start


def main():
    """
    Run different modules depending on the various domains i.e Internal Mobile and External
    Start Our test scripts

    """
    if check_for_dependencies():
        # start our pentest
        print("Starting our pentest")


if __name__ == "__main__":
    main()
