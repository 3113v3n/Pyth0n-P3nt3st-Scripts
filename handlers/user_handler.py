# trunk-ignore-all(black)
from utils.shared import InputValidators, Config
from .mobile_ui_handler import MobileInterface
from .internal_ui_handler import InternalInterface
from .external_ui_handler import ExternalInterface
from .vulnerability_ui import VulnerabilityInterface


class UserHandler:
    """Class will be responsible for handling user interactions with
    The different domains"""

    def __init__(
        self,
        filemanager,
        validator: InputValidators,
        bcolors,
        config: Config,
        mobile_ui: MobileInterface,
        internal_ui: InternalInterface,
        external_ui: ExternalInterface,
        va_ui: VulnerabilityInterface,
    ) -> None:
        self.config = config
        self.default_test_domains = []
        self.mobile_interface = mobile_ui
        self.internal_interface = internal_ui
        self.external_interface = external_ui
        self.vulnerability_interface = va_ui
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
                self.domain_variables = self.mobile_interface.user_interaction()
            case "internal":
                self.domain_variables = self.internal_interface.user_interaction(
                    get_subnet=self.get_user_subnet(),
                    color=self.color,
                    filemanager=self.filemanager,
                    config=self.config,
                )
            case "external":
                # TODO: [UNDER DEVELOPMENT !!]
                self.domain_variables = self.external_interface.user_interaction()
            case "va":
                self.domain_variables = self.vulnerability_interface.user_interaction(
                    self.validator, self.color,self.filemanager
                )
            case _:
                print(
                    f"{self.color.FAIL}[!] {self.domain.title()} is not a Valid testing domain{self.color.ENDC}"
                )
