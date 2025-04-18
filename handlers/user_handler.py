# trunk-ignore-all(black)
import sys
from utils.shared import Config
from handlers.screen import ScreenHandler
from handlers.helper_handler import HelpHandler
from handlers import FileHandler
from handlers.network_handler import get_network_interfaces,NetworkHandler


class UserHandler(FileHandler, Config, ScreenHandler):
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(self, helper_instance: HelpHandler, command_instance: callable) -> None:
        super().__init__()
        self.default_test_domains = []
        self.not_valid_domain = False
        self.domain = ""
        self.domain_variables = ""
        self.OPTIONS = self.set_test_options()
        self.helper_ = helper_instance
        self.command_ = command_instance
        self.debug = False
        self.formatted_question = (
            "\nWhat would you like to do?\n"
            f"{self.OPTIONS}\n"
            f"[Type '{self.BOLD}help{self.ENDC}' for info, or a number to choose a test domain]...\n "
        )

    @classmethod
    def reset_class_states(cls):
        """Reset the states of the class"""
        cls.default_test_domains = []
        cls.not_valid_domain = False
        cls.domain = ""
        cls.domain_variables = ""

    def set_test_options(self):
        # Create a list to store formatted options
        test_options = []
        for option in self.test_domains:
            # number to display on screen
            number = self.test_domains.index(option) + 1
            # Format each option with colors and spacing
            formatted_option = (
                # <30 align with width of 30 characters
                f"\n{number}. {self.OKGREEN}{option['domain']:<30} {self.ENDC}"
                f"[{self.OKGREEN} ENTER {number:<2}{self.ENDC}] {option['icon']}\n"
            )
            test_options.append(formatted_option)
            # set up default test domains

            self.default_test_domains.append(option["alias"])
        # Join the list into a single multi-line string
        return "".join(test_options)

    def start_domain_helper(self,
                            helper_function: callable,
                            **kwargs):
        if kwargs.get("helper_text"):
            text = kwargs.get("helper_text")
            helper_function(text)
        else:
            helper_function()

        input_text = ("[-] Would you like to start ? [ "
                      f"{self.OKGREEN}yes{self.ENDC} | {self.WARNING}no{self.ENDC}] ")
        valid_options = {"yes", "y", "no", "n", "quit", "exit"}

        response = self.validate_user_choice(
            valid_options, self.get_user_input, input_text)

        if response == "yes" or response == "y":
            self.command_.clear_screen()
        else:
            self.print_warning_message("Exiting Program...")
            return exit()

    def mobile_ui_handler(self):

        self.start_domain_helper(self.helper_.mobile_helper)
        while True:
            try:
                package_path = self.get_file_path(
                    "Please provide the Path to your mobile application(s)\nPath to File:  ",
                    self.check_folder_exists
                )

                applications = self.display_files_onscreen(
                    package_path,
                    self.display_saved_files,
                    display_applications=True
                )
                if applications:
                    return applications

            except (ValueError, FileExistsError) as error:
                self.print_error_message(error)

    def va_ui_handler(self):
        self.start_domain_helper(self.helper_.vulnerability_helper)
        while True:

            try:
                # Select Scanner [ Nessus | Rapid7 ]
                scanner_index = self.create_menu_selection(
                    menu_selection=f" {self.HEADER}Select Vulnerability Scanner used:{self.ENDC} \n\n",
                    options=self.vulnerability_scanners,
                    check_range_string="Scanner: ",
                    check_range_function=self.index_out_of_range_display,
                    start_color=self.HEADER,
                    end_color=self.ENDC,
                    scanner=True
                )
                selected_scanner = self.vulnerability_scanners[scanner_index]["alias"]

                # File format of the files [CSV or XLSX ]
                file_format_index = self.create_menu_selection(
                    menu_selection=f" \n {self.WARNING} Select the file "
                    f"format of the Scanned File(s):{self.ENDC} \n",
                    options=self.SCAN_FILE_FORMAT,
                    check_range_string="File Format: ",
                    check_range_function=self.index_out_of_range_display,
                    start_color=self.WARNING,
                    end_color=self.ENDC
                )

                file_extension = self.SCAN_FILE_FORMAT[file_format_index]
            

                self.print_info_message(
                    f"Scanning {file_extension.upper()} file extensions")
                # file extension ensures we display the correct file extensions

                search_dir = self.get_file_path(
                    "\nEnter Location Where your Scan files are located \n",
                    self.check_folder_exists
                )

                files_tuple = self.display_files_onscreen(
                    # display files depending on a user selected extension
                    search_dir, self.display_saved_files, scan_extension=file_extension
                )

                output_filename = self.get_output_filename()

                return {
                    "input_file": files_tuple,
                    "output": output_filename,
                    "scanner": selected_scanner,
                }

            except (FileExistsError, ValueError) as error:
                self.print_error_message(
                    message="Error in VA UI handler", exception_error=error)
                return None

    def external_ui_handler(self):
        self.start_domain_helper(self.helper_.external_helper)
        try:
            website_domain = (
                self.get_user_input(
                    "Enter domain to enumerate (example.domain.com)")
            )

            # TODO: strip https://

            return {"target_domain": website_domain}
        except Exception as error:
            self.print_error_message(error)

    @staticmethod
    def match_password(
            get_filepath_func: callable,
            is_file: callable,
            get_filename: callable,
            action: str):
        # Enter File Path to cracked hashes
        cracked_hashes = get_filepath_func(
            "\n[-] Enter full path to your cracked hashes \n",
            is_file
        )
        # Enter Path to Dumped hashes
        dumps = get_filepath_func(
            "\n[-] Enter full path to your dump [ntds] \n",
            is_file
        )
        # Enter file output path
        output_filename = get_filename()
        return {
            "hashes": cracked_hashes,
            "dumps": dumps,
            "filename": output_filename,
            "action": action
        }

    @staticmethod
    def test_user_password(
            get_user_input: callable,
            ip_validator: callable,
            validate: callable,
            get_filepath_func: callable,
            is_file: callable,
            display_text: str,
            domain_text: str,
            action: str):
        ip_error = "Invalid ip provided. Please enter a valid one"
        target = ip_validator(
            get_user_input,
            display_text,
            validate,
            ip_error
        )

        domain = get_user_input(domain_text)
        pass_list = get_filepath_func(
            "\n[-] Enter full path to your Password List file \n",
            is_file
        )

        return {
            "target": target,
            "domain": domain,
            "pass_file": pass_list,
            "filename": "Successful_Logins.txt",
            "action": action
        }

    def password_ui_handler(self):
        self.start_domain_helper(
            self.helper_.internal_helper, helper_text="hashfunction")
        target_text = "[-] Enter the IP address of your target [ 10.10.10.3 ] \n"
        domain_text = "[*] Enter the domain of your target [ testdomain.xy.z ] \n"
        valid_operations = {"generate", "test"}
        operation_text = (
            f"Type ({self.OKGREEN}generate{self.ENDC}) to Generate password list\n"
            f"Type ({self.OKGREEN}test{self.ENDC}) to test out your passwords \n")

        operation = self.validate_user_choice(valid_operations,
                                              self.get_user_input,
                                              operation_text)
        pass_handler = {
            "generate": lambda: self.match_password(self.get_file_path,
                                                    self.file_exists,
                                                    self.get_output_filename,
                                                    operation),
            "test": lambda: self.test_user_password(self.get_user_input,
                                                    self.get_valid_ip_addr,
                                                    self.validate_ip_addr,
                                                    self.get_file_path,
                                                    self.file_exists,
                                                    target_text,
                                                    domain_text,
                                                    operation)
        }
        start_handler = pass_handler.get(operation)
        if start_handler:
            return start_handler()

    def internal_ui_handler(self):
        """Handle internal assessment UI interactions"""

        self.start_domain_helper(
            self.helper_.internal_helper, helper_text="scanner")
        try:
            subnet = ""
            output_file = ""
            valid_actions = {"scan", "resume"}
            valid_interfaces = [iface 
                                for iface in get_network_interfaces()
                                if NetworkHandler()._is_interface_active(iface)
                                and not iface.startswith(("br-", "docker", "veth", "lo"))]
            if self.debug:
                print(f"DEBUG: Available active interfaces={valid_interfaces}")
                
            action = self.validate_user_choice(
                valid_actions,
                self.get_user_input,
                self.internal_mode_choice)
            interface = self.validate_user_choice(
                valid_interfaces,
                self.get_user_input,
                f"Enter a network interface to run your scan \n{valid_interfaces} "
            )

            if action == "resume":
                resume_ip = self.display_saved_files(
                    self.output_directory,
                    resume_scan=True
                )

                if resume_ip is None:
                    self.print_warning_message(
                        "No previous scan files found. Defaulting to scan mode.")
                    action = "scan"
                else:
                    output_file = self.filepath
                    while True:
                        cidr = self.get_cidr()
                        if cidr:
                            subnet = f"{resume_ip}/{cidr}"
                            break
                        else:
                            self.print_warning_message(
                                "Please enter a valid CIDR")
                            continue

            # If mode is scan or defaulted to scan
            if action == "scan":
                subnet = self.get_user_subnet()
                output_file = self.get_output_filename()

            return {
                "subnet": subnet,
                "action": action,
                "output": output_file,
                "interface": interface
            }

        except Exception as error:

            self.print_error_message(
                message="An error occurred", exception_error=error)
            mode = "scan"
            subnet = self.get_user_subnet()
            output_file = self.get_output_filename()
            return {
                "subnet": subnet,
                "mode": mode,
                "output": output_file,
            }

    @staticmethod
    def exit_program():
        return sys.exit(1)

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""
        # Reduce displayed index by 1 to avoid index error

        while True:
            try:
                selected_index = self.get_user_input(
                    self.formatted_question)
                if selected_index == "help":
                    self.domain = selected_index
                    return selected_index
                else:
                    selected_index = int(selected_index) - 1
                    if 0 <= selected_index < len(self.default_test_domains):
                        break
                    self.print_error_message(
                        message=f"❌ Invalid choice. Please enter a number between 1 and {len(self.default_test_domains)}"
                    )

            except ValueError:
                self.print_error_message(
                    message="❌ Invalid choice. Please enter a valid number")

        self.domain = self.default_test_domains[selected_index]
        return self.domain

    def get_user_subnet(self):
        # Validate subnet provided
        text = "\n[+] Please provide a valid subnet [10.0.0.0/24]\n"
        error_text = " Invalid IP address format provided"
        return self.get_valid_ip_addr(
            self.get_user_input,
            text,
            self.validate_ip_and_cidr,
            error_text)

    def get_cidr(self):
        # Validate CIDR
        cidr = "\n[+] Please provide a valid CIDR address that you were scanning previously [0-32]\n"
        error_txt = " Invalid CIDR provided"
        return self.get_valid_ip_addr(
            self.get_user_input,
            cidr,
            self.validate_cidr,
            error_txt
        )

    def get_valid_ip_addr(self,
                          get_user_input: callable,
                          input_text: str,
                          validator_func: callable,
                          error_text: str):
        while True:
            try:
                user_iput = get_user_input(input_text)
                if validator_func(user_iput):
                    break
                else:
                    raise ValueError(error_text)
            except ValueError as error:
                self.print_error_message(exception_error=error)
        return user_iput

    def help_me(self):
        self.helper_.main_program_helper()
        self.exit_program()

    def set_domain_variables(self, test_domain: str) -> dict:
        """Update the variable object with reference to the test domain provisioned

        param
            test-domain: The domain to be tested (
                    internal, external, password, mobile, va)

        returns
            dict: Domain-specific variables

        Raises
            ValueError: if Invalid-domain provided
            DomainError: If domain-specific operation fails
        """
        domain_handlers = {
            "internal": self.internal_ui_handler,
            "external": self.external_ui_handler,
            "mobile": self.mobile_ui_handler,
            "va": self.va_ui_handler,
            "password": self.password_ui_handler,
            "exit": self.exit_program,
            "help": self.help_me
        }

        try:
            if test_domain not in domain_handlers:
                raise ValueError(f"Invalid domain: {test_domain}")

            # Update output directory
            if test_domain not in {"exit", "help"}:
                self.update_output_directory(test_domain)

            # Get domain handler
            handler = domain_handlers[test_domain]
            self.domain_variables = handler()

            if not self.domain_variables:
                raise ValueError(
                    f"No variables returned for domain: {test_domain}")
            return self.domain_variables

        except Exception as error:
            error_msg = f"Error in {test_domain} domain: {str(error)}"
            self.print_error_message(
                message=f"Error in {test_domain} domain",
                exception_error=error)

            raise DomainError(error_msg) from error


class DomainError(Exception):
    """Custom exception for domain-related errors"""
    pass
