from __Utils__.colors import bcolors
from __Utils__.locate_dependencies import LocateDependencies
from __Handlers__.install_dependencies import InstallDepencies
from __Utils__.validators import Validators
from pprint import pprint

dependecies = LocateDependencies()
install_package = InstallDepencies()
validator_checks = Validators()


def check_for_dependencies():
    if len(dependecies.to_install) == 0:
        print(f"{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        ready_to_start = True
    else:
        ready_to_start = False
        print(
            f"{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {len(dependecies.to_install)} package(s)..{bcolors.ENDC}"
        )
        install_package.install_packages(dependecies.to_install)
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
        #print(validator_checks.validate_ip_addr("0.0.0.0"))


if __name__ == "__main__":
    main()
