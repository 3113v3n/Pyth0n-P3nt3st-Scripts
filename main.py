from pprint import pprint

# [Test Domains]
from domains import InternalPT

# [Handlers]
from handlers import (
    FileHandler,
    NetworkHandler,
    PackageHandler,
    UserHandler,
    VulnerabilityAnalysis,
)
from utils import Commands, InputValidators, bcolors

# [Utils]


# Initializers
validator = InputValidators()
## Handle packages
package = PackageHandler(Commands, bcolors)

## Handles file management
filemanager = FileHandler(bcolors, validator=validator)

## gathers user input
user = UserHandler(filemanager, validator, bcolors)

## Handles network related operations
network = NetworkHandler(filemanager, Commands)

## Vulnerability Analysis
vulnerability_analysis = VulnerabilityAnalysis(filemanager)


# [penetration Testing domains]
internal = InternalPT(filemanager=filemanager, network=network, colors=bcolors)

user_test_domain =  user.get_user_domain()


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

        case "va":

            formatted_vulns = vulnerability_analysis.analyze_csv(f"{user.domain_variables['input_file']}")
            vulnerability_analysis.sort_vulnerabilities(formatted_vulns,f"{user.domain_variables['output']}")
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

# internal.netexec_module()['relay-list'](
#     "output_directory/internal/home_w1f1_13-08-2024-11:02:30.csv",
#     "output_directory/internal/smb_relay.txt",
# )
# hashes = HashUtil()
# hashes.compare_hash_from_dump("aad3b435b51404eeaad3b435b51404ee", "test-data/test.ntds")
