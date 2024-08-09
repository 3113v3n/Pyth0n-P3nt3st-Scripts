# [Utils]
from utils.colors import bcolors
from utils.validators import InputValidators

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
validator = InputValidators()
## Handle packages
package = PackageHandler()

## Handles file management
filemanager = FileHandler(bcolors)

## gathers user input
user = UserHandler(filemanager, validator, bcolors)

## Handles network related operations
network = NetworkHandler(filemanager)


# [penetration Testing domains]
internal = InternalPT(filemanager=filemanager, network=network, colors=bcolors)


def packages_present() -> bool:
    # check if package list contains any missing packages
    if len(package.to_install) == 0:
        print(f"{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        return True
    else:
        print(
            f"{bcolors.WARNING}[!] Missing Packages Kindly be patient as\
            we install {len(package.to_install)} package(s)..{bcolors.ENDC}"
        )
        package.install_packages(package.to_install)
    return True


def user_interactions():

    match user.get_user_domain():  # one of Internal | Mobile | External
        case "internal":
            # initialize variables that will be used to test different Internal PT modules
            network.initialize_network_variables(user.domain_variables)
            internal.initialize_variables(
                mode=user.domain_variables["mode"],
                output_file=user.domain_variables["output"],
            )
            # TODO: [WORK IN PROGRESS]
            # Start scan to save live Ips
            internal.enumerate_hosts()
        case "mobile":
            # initialize variables that will be used to test different Mobile modules
            pass
        case "external":
            # initialize variables that will be used to test different External PT modules
            # out_put = filemanager.output_directory
            # external.initialize_variables(variables=domain_vars)
            # print(external.bbot_enum(out_put))
            pass
        case _:
            return


def main():
    """
    Run different modules depending on the various domains 
    i.e Internal Mobile and External
    """
    if packages_present():
        # start our pentest
        user_interactions()


if __name__ == "__main__":
    main()
