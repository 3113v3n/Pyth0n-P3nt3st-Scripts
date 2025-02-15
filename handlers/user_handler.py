# trunk-ignore-all(black)
from utils.shared import Config
from handlers import FileHandler
from utils.shared import Loader
from time import sleep

class UserHandler(FileHandler, Config):
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

    # User Interactions
    def loader(self, message: str, end_message: str):
        with Loader(message, end_message):
            for i in range(10):
                sleep(0.25)

    def mobile_ui_interaction(self):
        while True:
            try:
                self.loader("[*][*] Loading Mobile Assessment Module...",
                            "Starting Mobile Assessment...")
                
                package_path = input(
                    "Please provide the Path to your mobile application(s)\nPath to File:  "
                ).strip()
                # Show list of apks available
                if not self.check_folder_exists(package_path):
                    raise ValueError("No Such Folder exists")
                applications = self.display_saved_files(
                    package_path, display_applications=True
                )

                if applications:
                    return applications
                else:
                    raise FileExistsError("No Files Present in the provided Directory")
            except (ValueError, FileExistsError) as error:
                print(f"{self.FAIL}\n[!]{error}{self.ENDC}")

    @staticmethod
    def show_submenu(menu_selection: str,
                     options: list | tuple,
                     check_range_string: str,
                     check_range_function: callable,
                     start_color: str,
                     end_color: str,
                     **kwargs):
        print(menu_selection)
        for option in options:
            # Ensure both scanner menu and file extension are sorted for
            if "scanner" in kwargs:
                new_option = option["name"]
            else:
                new_option = option.upper()
            print(f" {start_color}[{options.index(option) + 1}]{end_color}"
                  f" {new_option}"
                  )
        return check_range_function(f"\n {check_range_string}", options)

    def va_ui_interaction(self):
        self.loader("[*][*] Loading Vulnerability Analysis Module...",
                            "Starting Vulnerability Analysis...")
        while True:

            try:
                # Select Scanner [ Nessus | Rapid7 ]
                scanner_index = self.show_submenu(
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
                file_format_index = self.show_submenu(
                    menu_selection=f" \n {self.WARNING} Select the file "
                                   f"format of the Scanned File(s):{self.ENDC} \n",
                    options=self.SCAN_FILE_FORMAT,
                    check_range_string="File Format: ",
                    check_range_function=self.index_out_of_range_display,
                    start_color=self.WARNING,
                    end_color=self.ENDC
                )

                file_extension = self.SCAN_FILE_FORMAT[file_format_index]
                print(f"\n{self.OKCYAN}Scanning {file_extension.upper()} file extensions{self.ENDC}")

                # file extension ensures we display the correct file extensions

                search_dir = input(
                    "\nEnter Location Where your files are located \n"
                ).strip()
                if not self.check_folder_exists(search_dir):
                    raise ValueError("No Such Folder exists")

                files_tuple = self.display_saved_files(
                    # display files depending on user selected extension
                    search_dir, scan_extension=file_extension
                )

                if files_tuple:
                    # Display all available CSV files

                    output_filename = input(
                        "[+] Provide a name for your output file: "
                    ).strip()

                    return {
                        "input_file": files_tuple,
                        "output": output_filename,
                        "scanner": selected_scanner,
                    }
                else:
                    raise FileExistsError("No Files Present in the provided Directory")

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
        try:
            while True:
                self.loader("[*][*] Loading Internal Assessment Module...",
                            "Starting Internal Assessment...")
                subnet = ""
                output_file = ""

                while True:
                # Check for empty input
                    mode = input(self.internal_mode_choice).strip().lower()
                    
                    if not mode:
                        print(f"{self.WARNING}\n[!] Please enter a valid choice (scan | resume){self.ENDC}")
                        continue
                    # Ensure correct mode is selected by user
                    if mode not in ["scan", "resume"]:
                        mode = input(self.internal_choice_error)
                        continue
                    break

                if mode == "resume":
                    """
                    Incase of resume module, get user subnet and append to the last ip obtained from the file
                    """

                    # returns an ip address if a file exists
                    # returns None if no file exists

                    resume_ip = self.display_saved_files(
                        self.output_directory, resume_scan=True
                    )

                    if resume_ip is None:
                        raise ValueError("No Previously saved file present")

                    # Output file will be the name of unresponsive file without text 'unresponsive_hosts'
                    output_file = self.filepath
                    while True:
                        cidr = self.get_cidr()
                        if cidr:
                            subnet = f"{resume_ip}/{cidr}"
                            break
                        else:
                            print(f"{self.WARNING}\n[!] Please enter a valid CIDR{self.ENDC}")
                            continue
                elif mode == "scan":
                    subnet = self.get_user_subnet()
                    output_file = input("\n[+] Provide a name for your output file: ").strip()

                return {
                    "subnet": subnet,
                    "mode": mode,
                    "output": output_file,
                }

        except ValueError as error:
            print(
                f"{self.FAIL}[!] Cant use this module, {error}{self.ENDC}"
            )
            print(f"\nDefaulting to {self.OKCYAN}SCAN{self.ENDC} mode")
            mode = "scan"
            subnet = self.get_user_subnet()
            output_file = input("\n[+] Provide a name for your output file: ").strip()



    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""
        # Reduce displayed index by 1 to avoid index error
        while True:
            try:
                selected_index = int(input(self.formatted_question).strip()) - 1
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

    def set_domain_variables(self, test_domain):
        """Update the variables object with reference to the test domain provisioned"""

        # Update the output directory with respective test domain
        # self.update_output_directory(test_domain)
        try:
            if test_domain == "internal":
                self.domain_variables = self.internal_ui_interaction()
            elif test_domain == "external":
                # TODO: [UNDER DEVELOPMENT !!]
                self.domain_variables = self.external_ui_interaction()
            elif test_domain == "mobile":
                # TODO: [UNDER DEVELOPMENT]
                self.domain_variables = self.mobile_ui_interaction()
            elif test_domain == "va":
                self.domain_variables = self.va_ui_interaction()
            else:
                print(f"{self.FAIL}Invalid domain provided{self.ENDC}")
                return
        except Exception as error:
            print(f"{self.FAIL}\n[!] Error setting domain variables {error}{self.ENDC}")
            raise

