# [Test Domains]
from domains import InternalAssessment, MobileAssessment, VulnerabilityAnalysis

# [Handlers]
from handlers import NetworkHandler, PackageHandler, UserHandler
from utils import MobileCommands, ProgressBar, Commands
from utils.shared import Bcolors


# [Utils]
# Initializers
def initialize_classes() -> dict:
    # Handle packages
    package = PackageHandler()

    # Terminal Commands
    command = Commands()

    # gathers user input
    user = UserHandler()

    # Handles network related operations
    network = NetworkHandler()

    # Mobile Commands
    mobile_commands = MobileCommands()

    # [penetration Testing domains]
    internal = InternalAssessment(network)
    vulnerability_analysis = VulnerabilityAnalysis()
    mobile = MobileAssessment(mobile_commands)

    return {
        "package": package,
        "user": user,
        "network": network,
        "internal": internal,
        "mobile": mobile,
        "vulnerability": vulnerability_analysis,
        "command": command
    }


def packages_present(user_test_domain: str, package) -> bool:
    # check if package list contains any missing packages
    missing_packages = package.get_missing_packages(user_test_domain)

    num_of_packages = 0

    if not missing_packages:
        # print(
        #     f"\n{Bcolors.OKBLUE}[+] All dependencies are present..{Bcolors.ENDC}")
        return True

    num_of_packages += len(missing_packages)
    print(
        f"\n{Bcolors.WARNING}[!] Missing Packages Kindly be patient as we install {
            num_of_packages} package(s).."
        f"{Bcolors.ENDC}"
    )
    # update to run check again
    try:
        package.install_packages(missing_packages)
        raise RuntimeError("[!] Failed to install some packages !")
    except RuntimeError as error:
        print(f"{Bcolors.FAIL}{error} {Bcolors.ENDC}")
        # return False

    return packages_present(user_test_domain, package)


def user_interactions(
        user,
        package,
        internal,
        network,
        mobile,
        vulnerability_analysis):
    """Handles user interaction based on selected testing domain"""
    user_test_domain = user.get_user_domain()
    user.set_domain_variables(user_test_domain)

    # Ensure all required packages are installed before proceeding
    if not packages_present(user_test_domain, package):
        print(
            f"{Bcolors.FAIL}[!] Unable to install required packages. Exiting .. {
                Bcolors.ENDC}"
        )
        return

    # Match user_test_domain (Internal | Mobile | External | VA)
    match user_test_domain:
        case "internal":

            # initialize variables that will be used to test different Internal PT modules
            network.initialize_network_variables(
                user.domain_variables, user_test_domain, ProgressBar)
            
            internal.initialize_variables(
                mode=user.domain_variables["mode"],
                output_file=user.domain_variables["output"],
            )
            # TODO: [WORK IN PROGRESS]
            # Start scan to save live Ips

            internal.enumerate_hosts()

        case "va":
            # Set scanner
            vulnerability_analysis.set_scanner(
                user.domain_variables["scanner"])
            input_file = user.domain_variables["input_file"]
            formatted_issues = vulnerability_analysis.analyze_scan_files(user_test_domain,
                                                                         input_file)

            # pprint(formatted_issues)
            vulnerability_analysis.sort_vulnerabilities(
                formatted_issues, f"{user.domain_variables['output']}"
            )

        case "mobile":

            # initialize variables that will be used to test different Mobile modules
            mobile_object = user.domain_variables
            mobile.initialize_variables(mobile_object)
            mobile.inspect_application_files(user_test_domain)

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
        user = init_classes["user"]
        package = init_classes["package"]
        internal = init_classes["internal"]
        network = init_classes["network"]
        vulnerability_analysis = init_classes["vulnerability"]
        mobile = init_classes["mobile"]
        command = init_classes["command"]

        def get_user_input():
            return (
                input(
                    f"[*] Would you like to {Bcolors.OKGREEN}EXIT the program{Bcolors.ENDC} "
                        f"{Bcolors.BOLD}('y' | 'n') ?{Bcolors.ENDC} "
                )
                .strip()
                .lower()
            )

        user_interactions(
            user=user,
            package=package,
            internal=internal,
            network=network,
            mobile=mobile,
            vulnerability_analysis=vulnerability_analysis,
        )
        ask_user = get_user_input()
        valid_choices = {"yes", "y", "no", "n"}
        while ask_user not in valid_choices:
            print(f"\n{Bcolors.WARNING}[!] {ask_user} is not a valid choice. Please Enter a valid choice: "
                  f"{Bcolors.ENDC}\n")
            ask_user = get_user_input()

        if ask_user in ["yes", "y"]:
            exit_menu = True
        else:
            # Clear screen
            command.clear_screen()


if __name__ == "__main__":
    main()
