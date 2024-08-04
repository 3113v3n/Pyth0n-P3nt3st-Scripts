from handlers.file_handler import FileHandler
from utils.validators import InputValidators


class UserHandler:
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(
        self, filemanager: FileHandler, validator: InputValidators, bcolors
    ) -> None:
        self.default_test_domains = ["mobile", "internal", "external"]
        self.color = bcolors
        self.not_valid_domain = False
        self.filemanager = filemanager
        self.validator = validator
        self.OPTIONS = (
            f"[ {self.color.HEADER}Mobile📱{self.color.ENDC} | "
            f"{self.color.HEADER}Internal 🖥️{self.color.ENDC} | "
            f"{self.color.HEADER}External 🌐{self.color.ENDC} ]\n"
        )
        self.formatted_question = (
            f"\nWhat domain do you want to test?" f"{self.OPTIONS}"
        )
        self.incase_of_error = (
            f"\n{self.color.FAIL}[!]{self.color.ENDC} Please choose one of: "
            f"{self.OPTIONS}"
        )
        self.mode_text = (
            f"\n[+] What mode would you like to run the scan with [{self.color.OKCYAN} SCAN | RESUME {self.color.ENDC}]"
            f"\n{self.color.OKCYAN}SCAN{self.color.ENDC} : scan new subnet\n"
            f"{self.color.OKCYAN}RESUME{self.color.ENDC} : resume previous scan\n "
        )
        self.wrong_choice = f"\n{self.color.FAIL}[!]{self.color.ENDC} Please select one of: [ {self.color.OKCYAN}SCAN | RESUME{self.color.ENDC} ]"
        # Object containing values respective to diff test domains
        self.domain = self.get_user_domain()
        self.domain_variables = self.set_domain_variables(self.domain)

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""

        user_input = input(self.formatted_question)
        while user_input not in self.default_test_domains:
            user_input = input(self.incase_of_error)
        self.domain = user_input.lower()
        return self.domain

    def set_domain_variables(self, test_domain):
        """Update the variables object with reference to the test domain provisioned"""

        # Update the output directory with respective test domain
        self.filemanager.update_output_directory(test_domain)

        match test_domain:
            case "mobile":
                # TODO: [UNDER DEVELOPMENT]
                print(f"Running Mobile scripts")
                package_name = input(
                    "Please provide the package name (com.example.packagename)\n"
                )
                # TODO: validate input is valid string
                self.domain_variables = {"package_name": package_name}
                return self.domain_variables
            case "internal":

                print(f"Running Internal PT modules")
                subnet = input(f"\n[+] Please provide a valid subnet [10.0.0.0/24]\n")

                # Validate subnet provided

                while not self.validator.validate_cidr(subnet):
                    subnet = input(
                        f"\n[+] Please provide an IP in the following format [10.0.0.0/24]\n"
                    )

                mode = input(self.mode_text).lower()

                # Ensure correct mode is selected by user
                while mode not in ["scan", "resume"]:
                    mode = input(self.wrong_choice)

                # TODO: if the choice is RESUME, show user list of available
                #   files to select from instead of promting them to enter filename
                if mode == "resume":
                    """Resumes scan from file with previously stored IPs
                    1. Select file to append to
                    2. Read the last line of the file
                    3. Start scan from the (current ip + 1)
                    4. Append successful results to file
                    """
                    # TODO: 1
                    resume_ip = self.filemanager.display_saved_files()
                    # output file
                    output_file = self.filemanager.full_file_path
                    subnet = f"{resume_ip}/{subnet.split('/')[1]}"
                else:
                    # TODO: file validations
                    output_file = input(f"[+] Provide a name for your output file: ")

                self.domain_variables = {
                    "subnet": subnet,
                    "mode": mode,
                    "output": output_file,
                }
                return self.domain_variables
            case "external":
                # TODO: [UNDER DEVELOPMENT !!]
                website_domain = input("Enter domain to enumerate (example.domain.com)")

                # TODO: strip https://
                self.domain_variables = {"target_domain": website_domain}

                return self.domain_variables
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
