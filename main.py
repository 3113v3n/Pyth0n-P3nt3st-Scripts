from pprint import pprint

# [Utils]
from __Utils__.colors import bcolors
from __Utils__.commands import Commands
from __Utils__.validators import Validators
from __Utils__.locate_dependencies import LocateDependencies

# [Handlers]
from __Handlers__.user_handler import UserInteraction
from __Handlers__.dependency_handler import InstallDepencies

# [Test Domains]
from __Domains__.external_pt import ExternalPT
from __Domains__.internal_pt import InternalPT
from __Domains__.mobile_pt import MobilePT

# Initializers
command = Commands()
dependencies = LocateDependencies(command)
install_package = InstallDepencies(command, bcolors)
validator_checks = Validators()
user = UserInteraction(bcolors)
# [penetration Testing domains]
internal = InternalPT(command)


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


def user_interactions():
    # Get Domain to test
    test_domain = user.get_user_domain()
    # set Variables depending on selected domain
    domain_vars = user.set_domain_variables(test_domain)
    if test_domain == "internal":
        internal.initialize_variables(domain_vars)
        print(
            f"Subnet: {internal.subnet}\nMode: {internal.mode}\nOutput File: {internal.output_file}"
        )


def main():
    """
    Run different modules depending on the various domains i.e Internal Mobile and External
    Start Our test scripts

    """
    if check_for_dependencies():
        # start our pentest
        print("Starting our pentest")
        user_interactions()


if __name__ == "__main__":
    main()
