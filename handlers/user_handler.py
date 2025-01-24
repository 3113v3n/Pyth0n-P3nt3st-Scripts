# trunk-ignore-all(black)
from utils.shared import Config, Validator, Bcolors
from handlers import FileHandler
import sys


class UserHandler(FileHandler, Config, Validator, Bcolors):
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
            f"\nWhat task do you want to perform?\n" f"{self.OPTIONS}\n=> "
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
                f"\n{self.OKGREEN}{number}. {option['domain']:<30} "
                f"[ ENTER {number:<2}] {option['icon']}{self.ENDC}\n"
            )
            test_options.append(formatted_option)
            # set up default test domains

            self.default_test_domains.append(option["alias"])
        # Join the list into a single multi-line string
        return "".join(test_options)

    # User Interactions

    def mobile_ui_interaction(self):
        while True:
            try:
                print("Running Mobile scripts\n")
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

    def va_ui_interaction(self):
        print("Running Vulnerability Analysis Module\n")

        while True:

            try:
                print(f"Select Vulnerability Scanner used: \n\n")
                for scanner in self.vulnerability_scanners:
                    print(
                        f" {self.HEADER}[{self.vulnerability_scanners.index(scanner) + 1}]"
                        f" {scanner["name"]}{self.ENDC}"
                    )
                scanner_index = self.index_out_of_range_display("\nScanner: ",
                                                                self.vulnerability_scanners)

                selected_scanner = self.vulnerability_scanners[scanner_index]["alias"]

                search_dir = input(
                    "\nEnter Location Where your files are located \n"
                ).strip()
                if not self.check_folder_exists(search_dir):
                    raise ValueError("No Such Folder exists")

                files_tuple = self.display_saved_files(
                    search_dir, display_csv=True
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
        print("\nRunning External PT modules")
        website_domain = (
            input("Enter domain to enumerate (example.domain.com)").strip().lower()
        )

        # TODO: strip https://

        return {"target_domain": website_domain}

    def internal_ui_interaction(self):
        print(" Running Internal PT modules ")
        subnet = ""
        mode = input(self.internal_mode_choice).strip().lower()
        output_file = ""

        # Ensure correct mode is selected by user
        while mode not in ["scan", "resume"]:
            mode = input(self.internal_choice_error)

        if mode == "resume":
            """
            Incase of resume module, get user subnet and append to the last ip obtained from the file
            """
            try:
                # returns an ip address if a file exists
                # returns None if no file exists

                resume_ip = self.display_saved_files(
                    self.output_directory, resume_scan=True
                )

                if resume_ip is None:
                    raise ValueError("No Previously saved file present")

                # Output file will be the name of unresponsive file without text 'unresponsive_hosts'
                output_file = self.filepath
                cidr = self.get_cidr()
                subnet = f"{resume_ip}/{cidr}"

            except ValueError as error:
                print(
                    f"{self.FAIL}[!] Cant use this module, {error}{self.ENDC}"
                )
                print(f"\nDefaulting to {self.OKCYAN}SCAN{self.ENDC} mode")
                mode = "scan"
                subnet = self.get_user_subnet()
                output_file = input("[+] Provide a name for your output file: ").strip()

        elif mode == "scan":
            subnet = self.get_user_subnet()
            output_file = input("[+] Provide a name for your output file: ").strip()

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
                selected_index = int(input(self.formatted_question).strip()) - 1
                if 0 <= selected_index < len(self.default_test_domains):
                    break
                print(
                    f"{self.FAIL}❌ Invalid choice. Please enter a number between 1 and {len(self.default_test_domains)}"
                    f"{self.ENDC}"
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
                    "[+] Please provide a valid CIDR address that you were scanning previously [0-32]\n"
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
        self.update_output_directory(test_domain)

        match test_domain:
            case "mobile":
                # TODO: [UNDER DEVELOPMENT]
                self.domain_variables = self.mobile_ui_interaction()
            case "internal":
                self.domain_variables = self.internal_ui_interaction()
            case "external":
                # TODO: [UNDER DEVELOPMENT !!]
                self.domain_variables = self.external_ui_interaction()
            case "va":
                self.domain_variables = self.va_ui_interaction()
            case "exit":
                sys.exit(1)
            case _:
                print(
                    f"{self.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.ENDC}"
                )
