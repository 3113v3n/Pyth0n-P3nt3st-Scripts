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
        self.domain = ""
        self.domain_variables = ""

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
            f"\n(In case you want to {self.color.BOLD}RESUME{self.color.ENDC} a scan,"
            f"please remember to {self.color.BOLD}{self.color.WARNING}manually update "
            f"the file{self.color.ENDC}{self.color.ENDC} \nwith the last scanned ip to "
            "allow resume scan from last scanned ip rather than last found ip address)\n"
            "\n Enter mode: ==> "
        )
        self.wrong_choice = f"\n{self.color.FAIL}[!]{self.color.ENDC} Please select one of: [ {self.color.OKCYAN}SCAN | RESUME{self.color.ENDC} ]"

    def get_user_domain(self) -> str:
        """Interacts with user to gather the target test domain"""

        user_input = input(self.formatted_question)
        while user_input not in self.default_test_domains:
            user_input = input(self.incase_of_error)
        self.domain = user_input.lower()
        self.set_domain_variables(self.domain)
        return self.domain

    def get_user_subnet(self):

        print(f"Running Internal PT modules")
        subnet = input(f"\n[+] Please provide a valid subnet [10.0.0.0/24]\n")

        # Validate subnet provided

        while not self.validator.validate_cidr(subnet):
            subnet = input(
                f"\n[+] Please provide an IP in the following format [10.0.0.0/24]\n"
            )
        return subnet

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
                subnet = self.get_user_subnet()
                mode = input(self.mode_text).lower()

                # Ensure correct mode is selected by user
                while mode not in ["scan", "resume"]:
                    mode = input(self.wrong_choice)

                if mode == "resume":
                    try:
                        # returns an ip address if a file exists
                        # returns None if no file exists

                        resume_ip = self.filemanager.display_saved_files()

                        if resume_ip == None:
                            raise ValueError("No Previously saved file present")

                        # output file
                        output_file = self.filemanager.full_file_path
                        subnet = f"{resume_ip}/{subnet.split('/')[1]}"

                    except ValueError as error:
                        print(
                            f"{self.color.FAIL}[!] Cant use this module, {error}{self.color.ENDC}"
                        )
                        print(
                            f"Defaulting to {self.color.OKCYAN}SCAN{self.color.ENDC} mode"
                        )
                        mode = "scan"
                        subnet = self.get_user_subnet()
                        output_file = input(
                            f"[+] Provide a name for your output file: "
                        )

                elif mode == "scan":
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
                print(f"\nRunning External PT modules")
                website_domain = input("Enter domain to enumerate (example.domain.com)")

                # TODO: strip https://
                self.domain_variables = {"target_domain": website_domain}

                return self.domain_variables
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
