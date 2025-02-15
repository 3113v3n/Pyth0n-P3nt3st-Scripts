from typing import Dict, Optional
import sys
# [Test Domains]
from domains import InternalAssessment, MobileAssessment, VulnerabilityAnalysis

# [Handlers]
from handlers import NetworkHandler, PackageHandler, UserHandler
from utils import MobileCommands, ProgressBar, Commands
from utils.shared import Bcolors


class PentestFramework:
    def __init__(self):
        self.classes = self.initialize_classes()
        self.exit_menu = False

    # [Utils]
    # Initializers
    @staticmethod
    def initialize_classes() -> dict:
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
            print(f"{Bcolors.FAIL}[!] Error initializing classes: {str(error)}{Bcolors.ENDC}")
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
            print(f"{Bcolors.OKGREEN}[+] Skipping package installation "
                  f"on unsupported OS: {Bcolors.ENDC}")
            return True

        missing_packages = package.get_missing_packages(user_test_domain)

        if not missing_packages:
            return True

        num_of_packages = len(missing_packages)
        print(
            f"\n{Bcolors.WARNING}[!] Missing Packages Kindly be patient "
            f"as we install {num_of_packages} package(s).."
            f"{Bcolors.ENDC}"
        )
        # update to run check again
        try:
            success = package.install_packages(missing_packages)
            if not success:
                return False
            return self.check_packages(user_test_domain)
        except RuntimeError as error:
            print(f"{Bcolors.FAIL}[!] Failed to install some packages: {error} {Bcolors.ENDC}")
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
        if not self.check_packages(user_test_domain):
            print(f"{Bcolors.FAIL}[!] Unable to install required packages. Exiting...{Bcolors.ENDC}")
            return

        # Match user_test_domain with appropriate handler
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
            print(f"{Bcolors.WARNING}[!] Invalid test domain selected{Bcolors.ENDC}")

    @staticmethod
    def get_user_input() -> str:
        """Get user input for program exit"""
        return (
            input(
                f"[*] Would you like to {Bcolors.OKGREEN}EXIT the program{Bcolors.ENDC} "
                f"{Bcolors.BOLD}('y' | 'n') ?{Bcolors.ENDC} "
            )
            .strip()
            .lower()
        )

    def run_program(self) -> None:
        """Main program loop"""
        while not self.exit_menu:
            try:
                user = self.classes["user"]
                test_domain = user.get_user_domain()
                user.set_domain_variables(test_domain)

                self.process_domain(test_domain)

                # Handle exit prompt
                exit_request = self.get_user_input()
                valid_user_choices = {"yes", "y", "no", "n"}

                while exit_request not in valid_user_choices:
                    print(f"\n{Bcolors.WARNING}[!] Invalid choice. Please enter 'y' or 'n':{Bcolors.ENDC}\n")
                    exit_request = self.get_user_input()

                if exit_request in ["yes", "y"]:
                    self.exit_menu = True
                else:
                    self.classes["command"].clear_screen()

            except KeyboardInterrupt:
                print(f"\n{Bcolors.WARNING}[!] Program interrupted by user{Bcolors.ENDC}")
                self.exit_menu = True
            except Exception as e:
                print(f"{Bcolors.FAIL}[!] An error occurred: {str(e)}{Bcolors.ENDC}")
                self.exit_menu = True


def main():
    """Entry point of the program"""
    try:
        framework = PentestFramework()
        framework.run_program()
    except Exception as e:
        print(f"{Bcolors.FAIL}[!] Critical error: {str(e)}{Bcolors.ENDC}")
        sys.exit(1)


if __name__ == "__main__":
    main()
