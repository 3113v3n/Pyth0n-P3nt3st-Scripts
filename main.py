from pprint import pprint

# [Utils]
from utils.colors import bcolors
from utils.commands import Commands
from utils.validators import Validators

# [Handlers]
from handlers.user_handler import UserHandler
from handlers.package_handler import PackageHandler
from handlers.file_handler import FileHandler
from handlers.network_handler import NetworkHandler

# [Test Domains]
from domains.external_pt import ExternalPT
from domains.internal_pt import InternalPT
from domains.mobile_pt import MobilePT

# Initializers
## run os level commands
command = Commands()

## Handle packages
package = PackageHandler(command, bcolors)

## runs validation on user inputs
validator_checks = Validators()

## gathers user input
user = UserHandler(bcolors)

## Handles file management
filemanager = FileHandler()

## Handles network related operations
network = NetworkHandler()


# [penetration Testing domains]
internal = InternalPT(command)
# external = ExternalPT(command,bcolors)


def packages_present() -> bool:
    # check if package list contains any missing packages
    if len(package.to_install) == 0:
        print(f"{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        ready_to_start = True
    else:
        ready_to_start = False
        print(
            f"{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {len(package.to_install)} package(s)..{bcolors.ENDC}"
        )
        package.install_packages(package.to_install)
    ready_to_start = True
    return ready_to_start


def user_interactions():
    # Get Domain to test [internal,mobile,external]
    test_domain = user.get_user_domain()

    # set Variables depending on selected domain
    domain_vars = user.set_domain_variables(test_domain)

    # Update output directory
    filemanager.update_output_directory(test_domain)

    match test_domain:
        case "internal":
            # initialize variables that will be used to test different Internal PT modules
            network.initialize_network_variables(domain_vars)
            internal.initialize_variables(
                mode=domain_vars["mode"], output_file=domain_vars["output"]
            )
            # TODO: [WORK IN PROGRESS]
            print(network.generate_possible_ips())

        case "mobile":
            # initialize variables that will be used to test different Mobile modules
            pass
        case "external":
            # initialize variables that will be used to test different External PT modules
            # out_put = filemanager.output_directory
            # external.initialize_variables(variables=domain_vars)
            # print(external.bbot_enum(out_put))
            pass


def main():
    """
    Run different modules depending on the various domains i.e Internal Mobile and External
    """
    if packages_present():
        # start our pentest
        user_interactions()


if __name__ == "__main__":
    main()
