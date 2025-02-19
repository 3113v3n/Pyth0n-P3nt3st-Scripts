from typing import Dict, Optional
import sys
# [Test Domains]
from domains import InternalAssessment, MobileAssessment, VulnerabilityAnalysis

# [Handlers]
from handlers import NetworkHandler, PackageHandler, UserHandler
from utils import MobileCommands, ProgressBar, Commands
from utils.shared import DisplayMessages, Bcolors


class PentestFramework(DisplayMessages):
    def __init__(self):
        self.classes = self.initialize_classes()
        self.exit_menu = False

    # [Utils]
    # Initializers

    def initialize_classes(self) -> dict:
        """Initialize all required classes for the framework

        Returns:
            Dictionary containing initialized class instances
        """
        try:
            network_instance = NetworkHandler()

            return {
                "package": PackageHandler(),
                "command": Commands(),
                "user": UserHandler(),
                "network": network_instance,
                "mobile": MobileAssessment(MobileCommands()),
                "vulnerability": VulnerabilityAnalysis(),
                "internal": InternalAssessment(network_instance)
            }
        except Exception as error:
            self.print_error_message(message="Error initializing classes", exception_error=error)
            sys.exit(1)

    def check_packages(self, user_test_domain: str) -> bool:
        """Check and install required packages for the selected domain

        Args:
            user_test_domain: Selected testing domain

        Returns:
            Boolean indicating if all required packages are present
        """

        package = self.classes["package"]

        # Initialize OS check
        if package.is_supported_os is None:
            package.is_supported_os = package._check_os_support()

        # If OS is not supported, continue without package checks
        if not package.is_supported_os:
            self.print_info_message("Skipping package installation on unsupported OS")
            return True

        missing_packages = package.get_missing_packages(user_test_domain)

        if not missing_packages:
            return True

        num_of_packages = len(missing_packages)
        self.print_warning_message(f"Missing Packages Kindly be patient as we install {num_of_packages} package(s)..")
        # update to run check again
        try:
            success = package.install_packages(missing_packages)
            if not success:
                return False
            return self.check_packages(user_test_domain)
        except RuntimeError as error:
            self.print_error_message(
                message="Failed to install some packages",
                exception_error=error
            )

            return False

    @staticmethod
    def handle_internal_assessment(user, network, internal):
        """Handle Internal penetration testing assessment"""
        # initialize variables that will be used to test different Internal PT modules
        network.initialize_network_variables(
            user.domain_variables, user.domain, ProgressBar)

        internal.initialize_variables(
            mode=user.domain_variables["mode"],
            output_file=user.domain_variables["output"],
        )

        internal.enumerate_hosts()

    @staticmethod
    def handle_vulnerability_assessment(user, vulnerability_analysis):
        """Handle Vulnerability analysis"""
        # Set scanner
        vulnerability_analysis.set_scanner(
            user.domain_variables["scanner"])
        input_file = user.domain_variables["input_file"]
        formatted_issues = vulnerability_analysis.analyze_scan_files(
            user.domain,
            input_file
        )

        # pprint(formatted_issues)
        vulnerability_analysis.sort_vulnerabilities(
            formatted_issues, f"{user.domain_variables['output']}"
        )

    @staticmethod
    def handle_mobile_assessment(user, mobile):
        """Handle mobile application assessment"""
        # initialize variables that will be used to test different Mobile modules
        mobile_object = user.domain_variables
        mobile.initialize_variables(mobile_object)
        mobile.inspect_application_files(user.domain)

    @staticmethod
    def handle_external_assessment(user):
        """Handle external assessment"""
        # initialize variables that will be used to test different External PT modules
        # external.initialize_variables(variables=domain_vars)
        # print(external.bbot_enum(out_put))
        pass

    def process_domain(self, user_test_domain: str) -> None:
        """Process the selected testing domain

        Args:
            user_test_domain: Selected testing domain
        """

        # Match user_test_domain with the appropriate handler
        handlers = {
            "internal": lambda: self.handle_internal_assessment(
                self.classes["user"],
                self.classes["network"],
                self.classes["internal"]
            ),
            "va": lambda: self.handle_vulnerability_assessment(
                self.classes["user"],
                self.classes["vulnerability"]
            ),
            "mobile": lambda: self.handle_mobile_assessment(
                self.classes["user"],
                self.classes["mobile"]
            ),
            "external": lambda: print("External assessment not implemented yet")
        }

        handler = handlers.get(user_test_domain)
        if handler:
            handler()
        else:
            self.print_error_message("Invalid test domain selected")

    @staticmethod
    def get_user_input() -> str:
        """Get user input for program exit"""
        while True:
            try:
                # flush any pending input
                sys.stdout.flush()
                sys.stdin.flush()

                choice = input(
                    f"[*] Would you like to {Bcolors.OKGREEN}EXIT the program{Bcolors.ENDC} "
                    f"{Bcolors.BOLD}('y' | 'n') ?{Bcolors.ENDC} "
                ).strip().lower()
                if choice in {'y', 'yes', 'n', 'no'}:
                    return choice
            except EOFError:
                # Handle EOF error
                continue
            except KeyboardInterrupt:
                # Exit on Ctrl+C
                return 'y'

    def run_program(self) -> None:
        """Main program loop"""
        while not self.exit_menu:
            try:
                user = self.classes["user"]
                test_domain = user.get_user_domain()

                # Check packages before getting user input
                if not self.check_packages(test_domain):
                    self.print_info_message("Required packages are missing. Installing them...")
                    continue

                # get user input and set domain variables
                user.set_domain_variables(test_domain)

                self.process_domain(test_domain)

                # Handle exit prompt

                valid_user_choices = {"yes", "y", "no", "n"}

                while True:
                    exit_request = self.get_user_input()
                    if exit_request in valid_user_choices:
                        break
                    self.print_warning_message("Invalid choice. Please enter 'y' or 'n':")
                if exit_request in {"yes", "y"}:
                    self.exit_menu = True
                else:
                    self.classes["command"].clear_screen()

            except KeyboardInterrupt:
                self.print_warning_message("Program interrupted by user")
                self.exit_menu = True
            except Exception as e:
                self.print_error_message(message="An error occurred", exception_error=e)


def main():
    """Entry point of the program"""
    global framework
    try:
        framework = PentestFramework()
        framework.run_program()
    except Exception as e:
        framework.print_error_message(message="Critical error", exception_error=e)

        sys.exit(1)


if __name__ == "__main__":
    main()
