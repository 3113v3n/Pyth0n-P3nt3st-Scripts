# trunk-ignore-all(black)
from utils.shared import Config
from handlers import FileHandler
from utils.shared import ScreenHandler


class UserHandler(FileHandler, Config, ScreenHandler):
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(self) -> None:
        super().__init__()
        self.default_test_domains = []
        self.not_valid_domain = False
        self.domain = ""
        self.domain_variables = ""
        self.OPTIONS = self.set_test_options()
        self.formatted_question = (
            f"\nWhat task would you like to perform?\n" f"{self.OPTIONS}\n=> "
        )

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

    def mobile_ui_interaction(self):
        while True:
            try:
                self.loader("[*][*] Loading Mobile Assessment Module...",
                            "Starting Mobile Assessment...")

                package_path = self.get_file_path(
                    "Please provide the Path to your mobile application(s)\nPath to File:  "
                )

                applications = self.display_files_onscreen(package_path,
                                                           self.display_saved_files,
                                                           display_applications=True)
                if applications:
                    return applications

            except (ValueError, FileExistsError) as error:
                print(f"{self.FAIL}\n[!]{error}{self.ENDC}")

    def va_ui_interaction(self):
        self.loader("[*][*] Loading Vulnerability Analysis Module...",
                    "Starting Vulnerability Analysis...")
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
                print(
                    f"\n{self.OKCYAN}Scanning {file_extension.upper()} file extensions{self.ENDC}")

                # file extension ensures we display the correct file extensions

                search_dir = self.get_file_path(
                    "\nEnter Location Where your Scan files are located \n"
                )

                files_tuple = self.display_files_onscreen(
                    # display files depending on user selected extension
                    search_dir, self.display_saved_files, scan_extension=file_extension
                )

                output_filename = self.get_output_filename()

                return {
                    "input_file": files_tuple,
                    "output": output_filename,
                    "scanner": selected_scanner,
                }

            except (FileExistsError, ValueError) as error:
                print(f"{self.FAIL}\n[!]{error}{self.ENDC}")

    def external_ui_interaction(self):
        self.loader("[*][*] Loading External Assessment Module...",
                    "Starting External Assessment...")
        website_domain = (
            input("Enter domain to enumerate (example.domain.com)").strip().lower()
        )

        # TODO: strip https://

        return {"target_domain": website_domain}

    def internal_ui_interaction(self):
        """Handle internal assessment UI interactions"""
        try:
            while True:
                self.loader("[*][*] Loading Internal Assessment Module...",
                            "Starting Internal Assessment...")
                subnet = ""
                output_file = ""

                while True:
                    mode = input(self.internal_mode_choice).strip().lower()
                    if not mode:
                        print(
                            f"{self.WARNING}\n[!] Please enter a valid choice (scan | resume){self.ENDC}")
                        continue
                    if mode not in ["scan", "resume"]:
                        mode = input(self.internal_choice_error)
                        continue
                    break

                if mode == "resume":
                    resume_ip = self.display_saved_files(
                        self.output_directory,
                        resume_scan=True
                    )

                    if resume_ip is None:
                        print(f"{self.WARNING}\n[!] No previous scan files found. Defaulting to scan mode.{self.ENDC}")
                        mode = "scan"
                    else:
                        output_file = self.filepath
                        while True:
                            cidr = self.get_cidr()
                            if cidr:
                                subnet = f"{resume_ip}/{cidr}"
                                break
                            else:
                                print(f"{self.WARNING}\n[!] Please enter a valid CIDR{self.ENDC}")
                                continue

                # If mode is scan or defaulted to scan
                if mode == "scan":
                    subnet = self.get_user_subnet()
                    output_file = self.get_output_filename()

                return {
                    "subnet": subnet,
                    "mode": mode,
                    "output": output_file,
                }

        except Exception as error:
            print(f"{self.FAIL}[!] An error occurred: {error}{self.ENDC}")
            mode = "scan"
            subnet = self.get_user_subnet()
            output_file = self.get_output_filename()
            return {
                "subnet": subnet,
                "mode": mode,
                "output": output_file,
            }

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""
        # Reduce displayed index by 1 to avoid index error
        while True:
            try:
                selected_index = int(
                    input(self.formatted_question).strip()) - 1
                if 0 <= selected_index < len(self.default_test_domains):
                    break
                print(
                    f"{self.FAIL}\n❌ Invalid choice. Please enter a number between 1 and "
                    f"{len(self.default_test_domains)}{self.ENDC}"
                )
            except ValueError:
                print(
                    f"{self.FAIL}\n❌ Invalid choice. Please enter a valid number{self.ENDC}"
                )

        self.domain = self.default_test_domains[selected_index]
        return self.domain

    def get_user_subnet(self):
        # Validate subnet provided

        while True:
            try:
                subnet = input(
                    "\n[+] Please provide a valid subnet [10.0.0.0/24]\n"
                ).strip()
                if self.validate_ip_and_cidr(subnet):
                    break
                else:
                    raise ValueError(" Invalid IP address format provided")
            except ValueError as error:
                print(f"{self.FAIL}\n[!]{error}{self.ENDC}")
        return subnet

    def get_cidr(self):
        # Validate CIDR
        while True:
            try:
                cidr = input(
                    "\n[+] Please provide a valid CIDR address that you were scanning previously [0-32]\n"
                ).strip()
                if self.validate_cidr(cidr):
                    break
                else:
                    raise ValueError(" Invalid CIDR provided")
            except ValueError as error:
                print(f"{self.FAIL}\n[!]{error}{self.ENDC}")
        return cidr

    def set_domain_variables(self, test_domain: str) -> dict:
        """Update the variables object with reference to the test domain provisioned
        
        param
            test-domain: The domain to be tested (internal, external,mobile,va)

        returns
            dict: Domain-specific variables

        Raises
            ValueError: if Invalid-domain provided
            DomainError: If domain specific operation fails
        """
        domain_handlers = {
            "internal": self.internal_ui_interaction,
            "external": self.external_ui_interaction,
            "mobile": self.mobile_ui_interaction,
            "va": self.va_ui_interaction
        }

        try:
            if test_domain not in domain_handlers:
                raise ValueError(f"Invalid domain: {test_domain}")

            # Update output directory
            self.update_output_directory(test_domain)

            # Get domain handler
            handler = domain_handlers[test_domain]
            self.domain_variables = handler()

            if not self.domain_variables:
                raise ValueError(f"No variables returned for domain: {test_domain}")
            return self.domain_variables

        except Exception as error:
            error_msg = f"Error in {test_domain} domain: {str(error)}"
            print(
                f"{self.FAIL}\n[!] {error_msg}{self.ENDC}")
            raise DomainError(error_msg) from error


class DomainError(Exception):
    """Custom exception for domain-related errors"""
    pass
