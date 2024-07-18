class UserInteraction:
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(self, text_color) -> None:
        self.domain = ""
        self.color = text_color
        self.domain_variables = {}

    def get_user_domain(self):
        formatted_question = (
            f"\nWhat domain do you want to test?"
            f"[ {self.color.HEADER}Mobile📱{self.color.ENDC} | "
            f"{self.color.HEADER}Internal 🖥️{self.color.ENDC} | "
            f"{self.color.HEADER}External 🌐{self.color.ENDC} ]\n"
        )
        user_input = input(formatted_question)
        self.domain = user_input.lower()
        return self.domain

    def set_domain_variables(self, test_domain):
        match test_domain:
            case "mobile":
                print(f"Running Mobile scripts")
                package_name = input(
                    "Please provide the package name (com.example.packagename)\n"
                )
                # TODO: validate input is valid string
                self.domain_variables = {"package_name": package_name}
                return self.domain_variables
            case "internal":
                mode_text = (
                    f"[+]\n What mode would you like to run the scan with [{self.color.OKCYAN}SCAN|RESUME{self.color.ENDC}]"
                    f"\n{self.color.OKCYAN}SCAN{self.color.ENDC} : scan new subnet\n"
                    f"{self.color.OKCYAN}RESUME{self.color.ENDC} : resume previous scan\n "
                )

                print(f"Running Internal PT modules")
                subnet = input(f"\n[+] Please provide a valid subnet [10.0.0.0/24]\n")
                # TODO : validate subnet provided
                mode = input(mode_text).lower()
                output_file = input(f"[+] Provide a name for your output file: ")
                self.domain_variables = {
                    "subnet": subnet,
                    "mode": mode,
                    "output": output_file,
                }
                return self.domain_variables
            case "external":
                website_domain = input("Enter domain to enumerate (example.domain.com)")
                # TODO: strip https://
                self.domain_variables = {"target_domain": website_domain}
                return self.domain_variables
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
