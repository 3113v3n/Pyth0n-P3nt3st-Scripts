# trunk-ignore-all(black)
from utils.shared import InputValidators, Config


class UserHandler:
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(
        self,
        filemanager,
        validator: InputValidators,
        bcolors,
        config: Config,
    ) -> None:
        self.config = config
        self.default_test_domains = []
        self.color = bcolors
        self.not_valid_domain = False
        self.filemanager = filemanager
        self.validator = validator
        self.domain = ""
        self.domain_variables = ""
        self.OPTIONS = self.set_test_options()
        self.formatted_question = (
            f"\nWhat task do you want to perform?\n" f"{self.OPTIONS}\n"
        )

    def set_test_options(self):
        # Create a list to store formatted options
        OPTIONS = []
        for option in self.config.test_domains:
            # number to display on screen
            number = self.config.test_domains.index(option) + 1
            # Format each option with colors and spacing
            formatted_option = (
                # <30 align with width of 30 characters
                f"{self.color.OKGREEN}{number}. {option['domain']:<30} "
                f"[ ENTER {number:<2}] {option['icon']}{self.color.ENDC}\n"
            )
            OPTIONS.append(formatted_option)
            # set up default test domains

            self.default_test_domains.append(option["alias"])
        # Join the list into a single multi-line string
        return "".join(OPTIONS)

    ## User Interactions

    def mobile_ui_interaction(self):
        while True:
            try:
                print("Running Mobile scripts\n")
                package_path = input(
                    "Please provide the Path to your mobile application(s)\nPath to File:  "
                ).strip()
                # Show list of apks available
                if not self.validator.check_folder_exists(package_path):
                    raise ValueError("No Such Folder exists")
                applications = self.filemanager.display_saved_files(
                    package_path, display_applications=True
                )

                if applications:
                    return applications
                else:
                    raise FileExistsError("No Files Present in the provided Directory")
            except (ValueError, FileExistsError) as error:
                print(f"{self.color.FAIL}\n[!]{error}{self.color.ENDC}")

    def va_ui_interaction(self):
        print("Running Vulnerability Analysis Module\n")

        while True:

            try:
                search_dir = input(
                    "\nEnter Location Where your files are located \n"
                ).strip()
                if not self.validator.check_folder_exists(search_dir):
                    raise ValueError("No Such Folder exists")

                files_tuple = self.filemanager.display_saved_files(
                    search_dir, display_csv=True
                )

                if files_tuple:
                    # Display all available CSV files

                    output_filename = input(
                        "[+] Provide a name for your output file: "
                    ).strip()

                    return {
                        "input_file": files_tuple,  # input_filename,
                        "output": output_filename,
                    }
                else:
                    raise FileExistsError("No Files Present in the provided Directory")

            except (FileExistsError, ValueError) as error:
                print(f"{self.color.FAIL}\n[!]{error}{self.color.ENDC}")

    def external_ui_interaction(self):
        print("\nRunning External PT modules")
        website_domain = (
            input("Enter domain to enumerate (example.domain.com)").strip().lower()
        )

        # TODO: strip https://

        return {"target_domain": website_domain}

    def internal_ui_interaction(self):
        print(" Running Internal PT modules ")
        subnet = self.get_user_subnet()
        mode = input(self.config.internal_mode_choice).strip().lower()

        # Ensure correct mode is selected by user
        while mode not in ["scan", "resume"]:
            mode = input(self.config.internal_choice_error)

        if mode == "resume":
            try:
                # returns an ip address if a file exists
                # returns None if no file exists

                resume_ip = self.filemanager.display_saved_files(
                    self.filemanager.output_directory
                )

                if resume_ip is None:
                    raise ValueError("No Previously saved file present")

                # output file
                output_file = self.filemanager.filepath
                subnet = f"{resume_ip}/{subnet.split('/')[1]}"

            except ValueError as error:
                print(
                    f"{self.color.FAIL}[!] Cant use this module, {error}{self.color.ENDC}"
                )
                print(f"\nDefaulting to {self.color.OKCYAN}SCAN{self.color.ENDC} mode")
                mode = "scan"
                subnet = self.get_user_subnet()
                output_file = input("[+] Provide a name for your output file: ").strip()

        elif mode == "scan":
            # TODO: file validations
            output_file = input("[+] Provide a name for your output file: ").strip()

        return {
            "subnet": subnet,
            "mode": mode,
            "output": output_file,
        }

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""
        # Reduce displayed index by 1 to avoid index error
        selected_index = int(input(self.formatted_question).strip()) - 1

        while selected_index not in range(len(self.default_test_domains)):
            selected_index = (
                int(
                    input(
                        f"{self.config.domain_select_error}" f"{self.OPTIONS}\n"
                    ).strip()
                )
                - 1
            )

        self.domain = self.default_test_domains[selected_index]
        # self.set_domain_variables(self.domain)
        print(self.domain)
        return self.domain

    def get_user_subnet(self):
        # Validate subnet provided

        while True:
            try:
                subnet = input(
                    "\n[+] Please provide a valid subnet [10.0.0.0/24]\n"
                ).strip()
                if self.validator.validate_cidr(subnet):
                    break
                else:
                    raise ValueError(" Invalid IP address format provided")
            except ValueError as error:
                print(f"{self.color.FAIL}\n[!]{error}{self.color.ENDC}")
        return subnet

    def set_domain_variables(self, test_domain):
        """Update the variables object with reference to the test domain provisioned"""

        # Update the output directory with respective test domain
        self.filemanager.update_output_directory(test_domain)

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
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
