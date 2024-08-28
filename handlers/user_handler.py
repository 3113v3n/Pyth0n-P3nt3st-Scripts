# trunk-ignore-all(black)
from utils.shared import InputValidators, Config


class UserHandler:
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(
        self, filemanager, validator: InputValidators, bcolors, config: Config
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
                f"[ Enter {option['alias']:<8}] {option['icon']}{self.color.ENDC}\n"
            )
            OPTIONS.append(formatted_option)
            # set up default test domains
            self.default_test_domains.append(option["alias"])

        # Join the list into a single multi-line string
        return "".join(OPTIONS)

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""

        user_input = input(self.formatted_question)
        while user_input not in self.default_test_domains:
            user_input = input(f"{self.config.domain_select_error}" f"{self.OPTIONS}\n")
        self.domain = user_input.lower()
        # self.set_domain_variables(self.domain)
        return self.domain

    def get_user_subnet(self):
        # Validate subnet provided

        while True:
            try:
                subnet = input("\n[+] Please provide a valid subnet [10.0.0.0/24]\n")
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
                print("Running Mobile scripts")
                package_name = input(
                    "Please provide the package name (com.example.packagename)\n"
                )
                # TODO: validate input is valid string
                self.domain_variables = {"package_name": package_name}
                return self.domain_variables
            case "internal":
                print(" Running Internal PT modules ")
                subnet = self.get_user_subnet()
                mode = input(self.config.internal_mode_choice).lower()

                # Ensure correct mode is selected by user
                while mode not in ["scan", "resume"]:
                    mode = input(self.config.internal_choice_error)

                if mode == "resume":
                    try:
                        # returns an ip address if a file exists
                        # returns None if no file exists

                        resume_ip = self.filemanager.display_saved_files()

                        if resume_ip is None:
                            raise ValueError("No Previously saved file present")

                        # output file
                        output_file = self.filemanager.full_file_path
                        subnet = f"{resume_ip}/{subnet.split('/')[1]}"

                    except ValueError as error:
                        print(
                            f"{self.color.FAIL}[!] Cant use this module, {error}{self.color.ENDC}"
                        )
                        print(
                            f"\nDefaulting to {self.color.OKCYAN}SCAN{self.color.ENDC} mode"
                        )
                        mode = "scan"
                        subnet = self.get_user_subnet()
                        output_file = input("[+] Provide a name for your output file: ")

                elif mode == "scan":
                    # TODO: file validations
                    output_file = input("[+] Provide a name for your output file: ")

                self.domain_variables = {
                    "subnet": subnet,
                    "mode": mode,
                    "output": output_file,
                }
                return self.domain_variables
            case "external":
                # TODO: [UNDER DEVELOPMENT !!]
                print("\nRunning External PT modules")
                website_domain = input("Enter domain to enumerate (example.domain.com)")

                # TODO: strip https://
                self.domain_variables = {"target_domain": website_domain}

                return self.domain_variables
            case "va":
                print("Running Vulnerability Analysis on your file\n")

                while True:

                    try:
                        input_filename = input(
                            "\n[+] Please provide a full path to the file you want to analyze: [CSV]\n"
                        )
                        # check if provided file exists
                        if self.validator.file_exists(input_filename):
                            # check if the file provided is of required extension
                            if self.validator.check_filetype(input_filename, "csv"):
                                # Exit the loop if file is valid
                                break
                            else:
                                raise ValueError(
                                    "Invalid file extension, only accepting CSV "
                                )
                        else:
                            raise FileNotFoundError("File Does not Exists")
                    except FileNotFoundError as error:
                        print(f"{self.color.FAIL}\n[!]{error}{self.color.ENDC}")

                    except ValueError as error:
                        print(f"{self.color.FAIL}\n[!]{error}{self.color.ENDC}")

                # Proceed to get the output filename
                output_filename = input("[+] Provide a name for your output file: ")
                self.domain_variables = {
                    "input_file": input_filename,
                    "output": output_filename,
                }

                return self.domain_variables
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
