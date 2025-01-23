# [Test Domains]
from domains import InternalAssessment, MobileAssessment, VulnerabilityAnalysis

# [Handlers]
from handlers import FileHandler, NetworkHandler, PackageHandler, UserHandler
from utils import Commands, Config, bcolors, MobileCommands, ProgressBar
from utils.shared import validators


# [Utils]
# Initializers
def initialize_classes() -> dict:
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

    return {"package": package,
            "user": user,
            "network": network,
            "internal": internal,
            "mobile": mobile,
            "vulnerability": vulnerability_analysis}


def packages_present(user_test_domain, package) -> bool:
    # check if package list contains any missing packages
    missing_packages = package.get_missing_packages(user_test_domain)

    num_of_packages = 0

    if not missing_packages:
        print(f"\n{bcolors.OKBLUE}[+] All dependencies are present..{bcolors.ENDC}")
        return True

    num_of_packages += len(missing_packages)
    print(
        f"\n{bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {num_of_packages} package(s).."
        f"{bcolors.ENDC}"
    )
    # update to run check again
    try:
        package.install_packages(missing_packages)
    except:
        print(f"{bcolors.FAIL}[!] Failed to install some packages ! {bcolors.ENDC}")
        return False

    return packages_present(user_test_domain, package)


def user_interactions(user, package, internal, network, mobile, vulnerability_analysis):
    """Handles user interaction based on selected testing domain"""
    user_test_domain = user.get_user_domain()
    user.set_domain_variables(user_test_domain)

    # Ensure all required packages are installed before proceeding
    # if not packages_present(user_test_domain, package):
    #     print(
    #         f"{bcolors.FAIL}[!] Unable to install required packages. Exiting .. {bcolors.ENDC}"
    #     )
    #     return

    # Match user_test_domain (Internal | Mobile | External | VA)
    match user_test_domain:
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
            # Set scanner
            vulnerability_analysis.set_scanner(user.domain_variables["scanner"])
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
    exit_menu = False

    while not exit_menu:
        # Initialize classes
        init_classes = initialize_classes()
        user = init_classes['user']
        package = init_classes['package']
        internal = init_classes['internal']
        network = init_classes['network']
        vulnerability_analysis = init_classes['vulnerability']
        mobile = init_classes['mobile']
        user_interactions(
            user=user,
            package=package,
            internal=internal,
            network=network,
            mobile=mobile,
            vulnerability_analysis=vulnerability_analysis)
        ask_user = (
            input(
                f"{bcolors.OKGREEN}[*] Would you like to EXIT the program {bcolors.BOLD}('Y' | 'N') ?{bcolors.ENDC} "
            )
            .strip()
            .lower()
        )
        if ask_user in ["yes", "y"]:
            exit_menu = True
        else:
            # Clear screen
            Commands.clear_screen()


if __name__ == "__main__":
    main()
