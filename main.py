# [Test Domains]
from domains import InternalAssessment, MobileAssessment, VulnerabilityAnalysis

# [Handlers]
from handlers import FileHandler, NetworkHandler, PackageHandler, UserHandler
from utils import Commands, Config, bcolors, MobileCommands, ProgressBar
from utils.shared import validators

# [Utils]
# Initializers

# Handle packages
package = PackageHandler(Commands, bcolors, Config)

# Handles file management
filemanager = FileHandler(bcolors, validator=validators)

# gathers user input
user = UserHandler(filemanager, validators, bcolors, Config)

# Handles network related operations
network = NetworkHandler(filemanager, Commands)

# Mobile Commands
mobile_commands = MobileCommands(Commands, filemanager, validators, bcolors, Config)

# [penetration Testing domains]
internal = InternalAssessment(filemanager=filemanager, network=network, colors=bcolors)
vulnerability_analysis = VulnerabilityAnalysis(filemanager, Config)
mobile = MobileAssessment(mobile_commands)

user_test_domain = user.get_user_domain()


def packages_present() -> bool:
    # check if package list contains any missing packages
    missing_packages = package.get_missing_packages(user_test_domain)

    num_of_packages = 0

    if len(missing_packages) == 0:
        print(f"\n{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        return True
    else:
        num_of_packages += len(missing_packages)
        print(
            f"\n{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {num_of_packages} package(s).."
            f"{bcolors.ENDC}"
        )
        # update to run check again

    return package.install_packages(missing_packages)


def user_interactions():
    user.set_domain_variables(user_test_domain)
    match user_test_domain:  # one of Internal | Mobile | External
        case "internal":
            # initialize variables that will be used to test different Internal PT modules
            network.initialize_network_variables(user.domain_variables, ProgressBar)
            internal.initialize_variables(
                mode=user.domain_variables["mode"],
                output_file=user.domain_variables["output"],
            )
            # TODO: [WORK IN PROGRESS]
            # Start scan to save live Ips
            internal.enumerate_hosts()

        case "va":
            formatted_issues = vulnerability_analysis.analyze_csv(
                user.domain_variables["input_file"]
            )
            vulnerability_analysis.sort_vulnerabilities(
                formatted_issues, f"{user.domain_variables['output']}"
            )

        case "mobile":
            # initialize variables that will be used to test different Mobile modules
            mobile_object = user.domain_variables
            mobile.initialize_variables(mobile_object)
            mobile.inspect_application_files()
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
    i.e. Internal Mobile and External
    """

    # if packages_present():  # TODO: change this back to True
    #     # start our pentest
    #     user_interactions()
    user_interactions()


if __name__ == "__main__":
    main()
