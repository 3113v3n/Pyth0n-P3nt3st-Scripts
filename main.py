import termios
import time
import sys
import os

# [Test Domains]
from domains import (
    InternalAssessment,
    MobileAssessment,
    VulnerabilityAnalysis,
    PasswordModule)
# [Utils]
from utils import (
    ProgressBar,
    Commands)
from utils.shared import Bcolors
# [Handlers]
from handlers import (
    NetworkHandler,
    PackageHandler,
    UserHandler,
    HelpHandler,
    ScreenHandler,
    InteractionHandler
)


class PentestFramework(ScreenHandler):
    def __init__(self):
        super().__init__()
        self.classes = self.initialize_classes()
        self.exit_menu = False
        self.debug = False

    # [Utils]
    # Initializers

    def initialize_classes(self) -> dict:
        """Initialize all required classes for the framework

        Returns:
            Dictionary containing initialized class instances
        """
        try:
            network_instance = NetworkHandler()
            helper_instance = HelpHandler()
            command_instance = Commands()

            return {
                "package": PackageHandler(),
                "command":  command_instance,
                "network": network_instance,
                "user": UserHandler(helper_instance, command_instance),
                "mobile":  MobileAssessment(),
                "vulnerability": VulnerabilityAnalysis(),
                "password": PasswordModule(),
                "internal": InternalAssessment(
                    network_instance,
                    helper_instance
                )
            }
        except Exception as error:
            self.print_error_message(
                message="Error initializing classes", exception_error=error)
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
            self.print_info_message(
                "Skipping package installation on unsupported OS")
            return True

        missing_packages = package.get_missing_packages(user_test_domain)

        if not missing_packages:
            return True

        num_of_packages = len(missing_packages)
        self.print_warning_message(
            f"Missing Packages Kindly be patient as we install {num_of_packages} package(s)..")
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

        if user.domain_variables["mode"] == "resume":
            # copies content of the instance
            network.existing_unresponsive_ips = user.existing_unresponsive_ips

        internal.initialize_variables(
            mode=user.domain_variables["mode"],
            output_file=user.domain_variables["output"])
        internal.enumerate_hosts()

    @staticmethod
    def handle_password_operations(user, password, **kwargs):
        """Handle Password related operations"""
        # Initialize Password class variables
        output_dir = user.output_directory
        generator_func = user.generate_unique_name
        variables = {}
        selected_action = ""

        if kwargs.get("user_data"):
            # Handles command line arguments
            variables = kwargs.get("user_data")
            selected_action = variables.get("action")
        else:
            variables = user.domain_variables
            selected_action = variables["action"]

        module_handler = {
            "generate": lambda: password.generate_passlist_from_hashes(
                variables,
                output_dir,
                generator_func),
            "test": lambda: password.test_valid_passwords(
                variables,
                generator_func,
                output_dir)
        }
        run_action = module_handler.get(selected_action)
       ## Run selected action
        if run_action:
            run_action()

    def handle_vulnerability_assessment(self, user, vulnerability_analysis):
        """Handle Vulnerability analysis"""
        try:

            # Set scanner
            scanner_type = user.domain_variables.get("scanner")
            vulnerability_analysis.set_scanner(scanner_type)

            input_file = user.domain_variables.get("input_file")
            formatted_issues = vulnerability_analysis.analyze_scan_files(
                user.domain,
                input_file
            )
            if formatted_issues is None:
                raise ValueError("No vulnerabilities found to process")

            # pprint(formatted_issues)
            output_filename = user.domain_variables.get('output')

            success = vulnerability_analysis.sort_vulnerabilities(
                formatted_issues,
                output_filename
            )
            if not success:
                raise ValueError("Failed to sort and save vulnerabilities")

              # Sync success message
            return True
        except Exception as e:
            self.print_error_message(
                message="Error in vulnerability assessment", exception_error=e)
            return False

    @staticmethod
    def handle_mobile_assessment(user, mobile):
        """Handle mobile application assessment"""
        # initialize variables that will be used to test different Mobile modules
        _vars = None
        test_domain = ""
        if isinstance(user, dict) and user.get("user_data"):
            _vars = user["user_data"]
            test_domain = _vars.get("module")
        else:
            _vars = user.domain_variables
            test_domain = user.domain

        mobile_testing_vars = _vars

        mobile.initialize_variables(mobile_testing_vars)
        mobile._inspect_files(test_domain)

    @staticmethod
    def handle_external_assessment(user):
        """Handle external assessment"""
        # initialize variables that will be used to test different External PT modules
        # external.initialize_variables(variables=domain_vars)
        # print(external.bbot_enum(out_put))
        pass

    def process_domain(self, user_test_domain: str, **kwargs) -> None:
        """Process the selected testing domain

        Args:
            user_test_domain: Selected testing domain
            kwargs: Handle command line arguments passed by user

        """

        if self.debug:
            self.print_debug_message(
                f"Commandline Arguments {self.classes["user"] if not kwargs.get("user_data") else kwargs}")
        # Match user_test_domain with the appropriate handler
        handlers = {
            # "internal": lambda: self.handle_internal_assessment(
            #     self.classes["user"] if not kwargs.get("user_data") else kwargs,
            #     self.classes["network"],
            #     self.classes["internal"]
            # ),
            # "va": lambda: self.handle_vulnerability_assessment(
            #     self.classes["user"]if not kwargs.get("user_data") else kwargs,
            #     self.classes["vulnerability"],
            # ),
            "mobile": lambda: self.handle_mobile_assessment(
                self.classes["user"] if not kwargs.get(
                    "user_data") else kwargs,
                self.classes["mobile"]
            ),
            "external": lambda: print("External assessment not implemented yet"),
            "password": lambda: self.handle_password_operations(
                self.classes["user"],
                self.classes["password"],
                user_data=kwargs.get("user_data")
            )

        }

        handler = handlers.get(user_test_domain)
        if handler:
            handler()
        else:
            self.print_error_message("Invalid test domain selected")

    @staticmethod
    def get_user_input() -> str:
        """Get user input for program exit"""
        def flush_input_output():
            """Flush any pending input and output"""
            try:
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
            except (ImportError, AttributeError):
                pass
            finally:
                sys.stdout.flush()

        while True:
            try:
                # Clear buffers
                flush_input_output()
                # Add a small delay to ensure all input is processed
                time.sleep(0.1)

                choice = input(
                    f"\n[*] Would you like to {Bcolors.WARNING}EXIT the program{Bcolors.ENDC} "
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

    def reset_class_states(self):
        """Reset the states of all classes"""
        try:
            self.classes = self.initialize_classes()
            if self.classes["mobile"]:
                self.classes["mobile"].reset_class_states()
            if self.classes["internal"]:
                self.classes["internal"].reset_class_states(
                    self.classes["network"])
            if self.classes["vulnerability"]:
                self.classes["vulnerability"].reset_class_states()
            if self.classes["network"]:
                self.classes["network"].reset_class_states()
            if self.classes["package"]:
                self.classes["package"].reset_class_states()
            if self.classes["user"]:
                self.classes["user"].reset_class_states()

        except Exception as e:
            self.print_error_message(
                message="Error resetting class states",
                exception_error=e)
            return

    def run_program(self) -> None:
        """Main program loop"""
        while not self.exit_menu:
            try:
                # Reset state at the start of each iteration
                self.reset_class_states()

                user = self.classes["user"]
                test_domain = user.get_user_domain()

                # Check packages before getting user input
                if not self.check_packages(test_domain):
                    self.print_info_message(
                        "Required packages are missing. Installing them...")
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
                    self.print_warning_message(
                        "Invalid choice. Please enter 'y' or 'n':")
                if exit_request in {"yes", "y"}:
                    self.exit_menu = True
                else:
                    self.classes["command"].clear_screen()

            except KeyboardInterrupt:
                self.print_error_message("Program interrupted by user")
                self.exit_menu = True
            except Exception as e:
                self.print_error_message(
                    message="An error in Main Program occurred", exception_error=e)

    def run_program_interactively(self, user_data: dict) -> None:
        """Run Interactive version of the program
        Args:
            user_data: Dictionary containing user data
        """
        try:
            # Reset state at the start of each iteration
            self.reset_class_states()
            user = self.classes["user"]
            test_domain = user_data.get("module")

            # Update test domain if need be
            user.update_output_directory(test_domain)

            # Check packages before getting user input
            if not self.check_packages(test_domain):
                self.print_info_message(
                    "Required packages are missing. Installing them...")

            # print(f"User command line arguments are:\n {user_data}")
            self.process_domain(test_domain, user_data=user_data)

        except KeyboardInterrupt:
            self.print_error_message("Program interrupted by user")
            self.exit_menu = True
        except Exception as e:
            self.print_error_message(
                message="An error in Main Program occurred", exception_error=e)


def main():
    """Entry point of the program"""
    framework = PentestFramework()
    _interaction = InteractionHandler()
    try:
        _interaction.main()
        # Check if command line arguments are used
        use_cmdline_args = _interaction.argument_mode
        if not use_cmdline_args:
            framework.run_program()
        else:
            # Handle command line args here
            _interaction.arguments["use_args"] = use_cmdline_args
            framework.run_program_interactively(_interaction.arguments)
    except Exception as e:
        framework.print_error_message(
            message="Critical error", exception_error=e)
        sys.exit(1)


if __name__ == "__main__":
    main()
