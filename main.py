# [Utils]
from utils import bcolors, InputValidators

# [Handlers]
from handlers import (
    UserHandler, PackageHandler, FileHandler, NetworkHandler
)

# [Test Domains]
from domains import (ExternalPT, InternalPT, MobilePT)

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

user_test_domain = user.get_user_domain()

def packages_present() -> bool:
    # check if package list contains any missing packages
    if len(package.get_missing_packages(user_test_domain)) == 0:
        print(f"\n{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        return True
    else:
        print(
            f"\n{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {len(package.get_missing_packages(user_test_domain))} package(s)..{bcolors.ENDC}"
        )
        package.install_packages(package.get_missing_packages(user_test_domain))
    return True


def user_interactions():
    user.set_domain_variables(user_test_domain)
    match user_test_domain:  # one of Internal | Mobile | External
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
    #hashes = HashUtil()
    #hashes.compare_hash_from_dump("aad3b435b51404eeaad3b435b51404ee", "test-data/test.ntds")
