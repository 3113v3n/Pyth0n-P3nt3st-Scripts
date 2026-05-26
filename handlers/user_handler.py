# trunk-ignore-all(black)
import sys
from utils.shared import Config
from handlers.navigation import BackToMainMenu, BackToPreviousMenu
from handlers.screen import ScreenHandler
from handlers.helper_handler import HelpHandler
from handlers import FileHandler
from handlers.network_handler import get_network_interfaces,NetworkHandler
from utils.internal.scan_session import ScanSessionStore


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
        self.menu_state = {}
        self.formatted_question = (
            "\nWhat would you like to do?\n"
            f"{self.OPTIONS}\n"
            f"[Type '{self.BOLD}help{self.ENDC}' for info, or a number to choose a test domain]...\n "
        )

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.default_test_domains = []
        self.not_valid_domain = False
        self.domain = ""
        self.domain_variables = ""
        self.menu_state = {}

    @classmethod
    def reset_class_states(cls):
        """Deprecated — use reset_state() on the instance instead."""
        cls.default_test_domains = []
        cls.not_valid_domain = False
        cls.domain = ""
        cls.domain_variables = ""
        cls.menu_state = {}

    def _get_menu_state(self, module: str) -> dict:
        state = self.menu_state.get(module)
        if isinstance(state, dict):
            return state
        state = {}
        self.menu_state[module] = state
        return state

    def _clear_all_menu_state(self) -> None:
        self.menu_state = {}

    def _go_to_previous_step(self, step: int) -> int:
        if step <= 0:
            raise BackToMainMenu()
        self.print_info_message("Returning to previous menu step.")
        return step - 1

    def set_test_options(self):
        # Create a list to store formatted options
        test_options = []
        for option in self.test_domains:
            # number to display on screen
            number = self.test_domains.index(option) + 1
            # Format each option with colors and spacing
            formatted_option = (
                # <30 align with width of 30 characters
                f"\n{number}. {self.HIGHLIGHT}{option['domain']:<30} {self.ENDC}"
                f"[{self.INFO} ENTER {number:<2}{self.ENDC}] {option['icon']}\n"
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
        self.show_navigation_hint()

        input_text = (
            "[-] Would you like to start ? [ "
            f"{self.OKGREEN}yes{self.ENDC} | {self.WARNING}no{self.ENDC} ] "
        )
        valid_options = {"yes", "y", "no", "n"}

        try:
            response = self.validate_user_choice(
                valid_options, self.get_user_input, input_text
            )
        except BackToPreviousMenu as error:
            raise BackToMainMenu() from error

        if response == "yes" or response == "y":
            self.command_.clear_screen()
        else:
            raise BackToMainMenu()

    def mobile_ui_handler(self):
        state = self._get_menu_state("mobile")
        self.start_domain_helper(self.helper_.mobile_helper)
        step = 0

        while True:
            try:
                if step == 0:
                    taxonomy_raw = self.prompt_format(
                        "Taxonomy tags [none | masvs | mastg | both] (default: both): "
                    ).strip().lower()
                    state["taxonomy"] = (
                        taxonomy_raw
                        if taxonomy_raw in {"none", "masvs", "mastg", "both"}
                        else "both"
                    )
                    step += 1
                    continue

                if step == 1:
                    profile_raw = self.prompt_format(
                        "Taxonomy profile [strict | balanced | aggressive] (default: balanced): "
                    ).strip().lower()
                    state["taxonomy_profile"] = (
                        profile_raw
                        if profile_raw in {"strict", "balanced", "aggressive"}
                        else "balanced"
                    )
                    step += 1
                    continue

                if step == 2:
                    package_path = self.get_file_path(
                        "Please provide the path to a directory containing your mobile application(s)\nPath to Directory:  ",
                        self.check_folder_exists,
                    )
                    self.files = []
                    self.find_files(package_path)
                    file_collection = self._get_file_collections()
                    applications = file_collection["applications"]
                    if not applications:
                        raise FileNotFoundError(
                            f"No APK/IPA files found in: {package_path}"
                        )

                    state["source_path"] = package_path
                    state["applications"] = applications
                    total_apps = len(applications)
                    self.print_info_message(
                        "Applications discovered in directory",
                        file_path=f"{package_path} ({total_apps} found)",
                    )

                    if total_apps == 1:
                        self.print_info_message(
                            "Only one application found; scanning that app."
                        )
                        app = dict(applications[0])
                        app["taxonomy"] = state["taxonomy"]
                        app["taxonomy_profile"] = state["taxonomy_profile"]
                        state["scan_mode"] = "single"
                        self.domain_variables = app
                        return app

                    step += 1
                    continue

                if step == 3:
                    mode = self.validate_user_choice(
                        {"single", "s", "all", "a"},
                        self.get_user_input,
                        "Select scan mode [single | all]: ",
                    )
                    state["scan_mode"] = "all" if mode in {"all", "a"} else "single"
                    if state["scan_mode"] == "all":
                        result = {
                            "scan_mode": "all",
                            "taxonomy": state["taxonomy"],
                            "taxonomy_profile": state["taxonomy_profile"],
                            "source_path": state["source_path"],
                            "applications": state["applications"],
                        }
                        self.domain_variables = result
                        return result
                    step += 1
                    continue

                self.files = state.get("applications", [])
                self._display_file_options()
                selected_app = self.index_out_of_range_display(
                    "Select the application to scan: ", self.files
                )
                app = dict(self.files[selected_app])
                app["taxonomy"] = state["taxonomy"]
                app["taxonomy_profile"] = state["taxonomy_profile"]
                state["selected_application"] = app["filename"]
                self.domain_variables = app
                return app

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise
            except (ValueError, FileExistsError, FileNotFoundError) as error:
                self.print_error_message(error)

    def va_ui_handler(self):
        state = self._get_menu_state("va")
        self.start_domain_helper(self.helper_.vulnerability_helper)
        step = 0

        while True:
            try:
                if step == 0:
                    scanner_index = self.create_menu_selection(
                        menu_selection=f" {self.HEADER}Select Vulnerability Scanner used:{self.ENDC} \n\n",
                        options=self.vulnerability_scanners,
                        check_range_string="Scanner: ",
                        check_range_function=self.index_out_of_range_display,
                        start_color=self.HEADER,
                        end_color=self.ENDC,
                        scanner=True,
                    )
                    state["scanner"] = self.vulnerability_scanners[scanner_index]["alias"]
                    step += 1
                    continue

                if step == 1:
                    file_format_index = self.create_menu_selection(
                        menu_selection=f" \n {self.WARNING} Select the file "
                        f"format of the Scanned File(s):{self.ENDC} \n",
                        options=self.SCAN_FILE_FORMAT,
                        check_range_string="File Format: ",
                        check_range_function=self.index_out_of_range_display,
                        start_color=self.WARNING,
                        end_color=self.ENDC,
                    )
                    state["file_extension"] = self.SCAN_FILE_FORMAT[file_format_index]
                    self.print_info_message(
                        f"Scanning {state['file_extension'].upper()} file extensions"
                    )
                    step += 1
                    continue

                if step == 2:
                    state["search_dir"] = self.get_file_path(
                        "\nEnter Location Where your Scan files are located \n",
                        self.check_folder_exists,
                    )
                    step += 1
                    continue

                if step == 3:
                    files_tuple = self.display_files_onscreen(
                        state["search_dir"],
                        self.display_saved_files,
                        scan_extension=state["file_extension"],
                    )
                    if not files_tuple:
                        self.print_warning_message(
                            "No valid scan files were selected. Please choose another location."
                        )
                        step = 2
                        continue
                    state["input_file"] = files_tuple
                    step += 1
                    continue

                state["output"] = self.get_output_filename()
                result = {
                    "input_file": state["input_file"],
                    "output": state["output"],
                    "scanner": state["scanner"],
                }
                self.domain_variables = result
                return result

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise
            except (FileExistsError, FileNotFoundError, ValueError) as error:
                self.print_error_message(
                    message="Error in VA UI handler", exception_error=error
                )

    def external_ui_handler(self):
        state = self._get_menu_state("external")
        self.start_domain_helper(self.helper_.external_helper)
        from utils.external.external_constants import (
            DEFAULT_PHASES,
            SAFE_OPERATOR_TAG_DEFAULT,
        )
        step = 0

        while True:
            try:
                if step == 0:
                    raw = self.get_user_input(
                        "Enter domain to enumerate (example.domain.com): "
                    )
                    domain = raw.replace("https://", "").replace("http://", "").strip("/")
                    if not self.validate_domain(domain):
                        self.print_warning_message(
                            f"'{raw}' is not a valid domain. Try again."
                        )
                        continue
                    state["target_domain"] = domain
                    step += 1
                    continue

                if step == 1:
                    phase_text = (
                        f"\n[+] Phases to run (comma-separated). "
                        f"Press Enter for ALL.\n    Available: {', '.join(DEFAULT_PHASES)}\n"
                    )
                    raw_phases = self.prompt_format(phase_text).strip()
                    phases = tuple(
                        p.strip().lower() for p in raw_phases.split(",") if p.strip()
                    ) or DEFAULT_PHASES
                    unknown = [p for p in phases if p not in DEFAULT_PHASES]
                    if unknown:
                        self.print_warning_message(
                            f"Ignoring unknown phase(s): {unknown}. Falling back to ALL."
                        )
                        phases = DEFAULT_PHASES
                    state["phases"] = phases
                    step += 1
                    continue

                if step == 2:
                    safe_mode_choice = self.validate_user_choice(
                        {"yes", "y", "no", "n"},
                        self.get_user_input,
                        "Enable safe mode (lower-impact external profile)? [yes|no]: ",
                    )
                    state["safe_mode"] = safe_mode_choice in {"yes", "y"}
                    if not state["safe_mode"]:
                        state["operator_tag"] = ""
                        result = {
                            "target_domain": state["target_domain"],
                            "phases": state["phases"],
                            "safe_mode": False,
                            "operator_tag": "",
                        }
                        self.domain_variables = result
                        return result
                    step += 1
                    continue

                operator_tag = self.prompt_format(
                    "Operator tag for audit headers/metadata "
                    f"[default: {SAFE_OPERATOR_TAG_DEFAULT}]: ",
                    path=True,
                )
                state["operator_tag"] = operator_tag or SAFE_OPERATOR_TAG_DEFAULT

                result = {
                    "target_domain": state["target_domain"],
                    "phases": state["phases"],
                    "safe_mode": bool(state["safe_mode"]),
                    "operator_tag": state["operator_tag"],
                }
                self.domain_variables = result
                return result

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise
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
        state = self._get_menu_state("password")
        self.start_domain_helper(
            self.helper_.internal_helper, helper_text="hashfunction")
        target_text = "[-] Enter the IP address of your target [ 10.10.10.3 ] \n"
        domain_text = "[*] Enter the domain of your target [ testdomain.xy.z ] \n"
        valid_operations = {"generate", "test"}
        operation_text = (
            f"Type ({self.OKGREEN}generate{self.ENDC}) to Generate password list\n"
            f"Type ({self.OKGREEN}test{self.ENDC}) to test out your passwords \n")
        step = 0

        while True:
            try:
                if step == 0:
                    state["action"] = self.validate_user_choice(
                        valid_operations,
                        self.get_user_input,
                        operation_text,
                    )
                    step += 1
                    continue

                if state["action"] == "generate":
                    if step == 1:
                        state["hashes"] = self.get_file_path(
                            "\n[-] Enter full path to your cracked hashes \n",
                            self.file_exists,
                        )
                        step += 1
                        continue
                    if step == 2:
                        state["dumps"] = self.get_file_path(
                            "\n[-] Enter full path to your dump [ntds] \n",
                            self.file_exists,
                        )
                        step += 1
                        continue
                    state["filename"] = self.get_output_filename()
                    result = {
                        "hashes": state["hashes"],
                        "dumps": state["dumps"],
                        "filename": state["filename"],
                        "action": "generate",
                    }
                    self.domain_variables = result
                    return result

                if step == 1:
                    ip_error = "Invalid ip provided. Please enter a valid one"
                    state["target"] = self.get_valid_ip_addr(
                        self.get_user_input,
                        target_text,
                        self.validate_ip_addr,
                        ip_error,
                    )
                    step += 1
                    continue
                if step == 2:
                    state["domain"] = self.get_user_input(domain_text)
                    step += 1
                    continue
                state["pass_file"] = self.get_file_path(
                    "\n[-] Enter full path to your Password List file \n",
                    self.file_exists,
                )
                result = {
                    "target": state["target"],
                    "domain": state["domain"],
                    "pass_file": state["pass_file"],
                    "filename": "Successful_Logins.txt",
                    "action": "test",
                }
                self.domain_variables = result
                return result

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise

    def internal_ui_handler(self):
        """Handle internal assessment UI interactions"""

        state = self._get_menu_state("internal")
        self.start_domain_helper(
            self.helper_.internal_helper, helper_text="scanner")
        step = 0
        valid_actions = {"scan", "resume"}

        # [Performance] Reuse a single NetworkHandler instance for all checks
        # instead of creating a new one per interface.
        _nh = NetworkHandler()
        valid_interfaces = [
            iface
            for iface in get_network_interfaces()
            if _nh._is_interface_active(iface)
            and not iface.startswith(("br-", "docker", "veth", "lo"))
        ]
        if self.debug:
            print(f"DEBUG: Available active interfaces={valid_interfaces}")

        while True:
            try:
                if step == 0:
                    state["action"] = self.validate_user_choice(
                        valid_actions,
                        self.get_user_input,
                        self.internal_mode_choice,
                    )
                    state.pop("resume_requires_manual", None)
                    step += 1
                    continue

                if state["action"] == "scan":
                    if step == 1:
                        state["interface"] = self.validate_user_choice(
                            set(valid_interfaces),
                            self.get_user_input,
                            f"Enter a network interface to run your scan \n{valid_interfaces} ",
                        )
                        step += 1
                        continue
                    if step == 2:
                        state["subnet"] = self.get_user_subnet()
                        step += 1
                        continue

                    state["output"] = self.get_output_filename()
                    result = {
                        "subnet": state["subnet"],
                        "action": "scan",
                        "output": state["output"],
                        "interface": state["interface"],
                    }
                    self.domain_variables = result
                    return result

                if step == 1:
                    resume_ip = self.display_saved_files(
                        self.output_directory,
                        resume_scan=True,
                    )
                    if resume_ip is None:
                        self.print_warning_message(
                            "No previous scan files found. Returning to action selection."
                        )
                        step = 0
                        continue

                    state["resume_ip"] = resume_ip
                    state["output"] = self.filepath
                    session_store = ScanSessionStore(self.output_directory)
                    session = session_store.get_session_by_unresponsive_file(state["output"])

                    if session:
                        saved_subnet = session.get("subnet_cidr")
                        saved_snapshot = session.get("interface_snapshot") or {}
                        matched_interface = session_store.find_similar_active_interface(
                            saved_snapshot
                        )
                        if not saved_subnet:
                            raise ValueError(
                                "Saved scan session has no subnet metadata for resume."
                            )
                        if not matched_interface:
                            raise ValueError(
                                "Resume blocked: no similar active interface detected "
                                "for the saved scan session."
                            )
                        state["subnet"] = saved_subnet
                        state["interface"] = matched_interface
                        self.print_info_message(
                            "Resume metadata loaded from saved scan session"
                        )
                        self.print_info_message(
                            "Using subnet", file_path=state["subnet"]
                        )
                        self.print_info_message(
                            "Using interface", file_path=state["interface"]
                        )
                        result = {
                            "subnet": state["subnet"],
                            "action": "resume",
                            "output": state["output"],
                            "interface": state["interface"],
                        }
                        self.domain_variables = result
                        return result

                    self.print_warning_message(
                        "No saved session metadata found for this file. "
                        "Falling back to manual CIDR resume."
                    )
                    state["resume_requires_manual"] = True
                    step += 1
                    continue

                if step == 2:
                    state["interface"] = self.validate_user_choice(
                        set(valid_interfaces),
                        self.get_user_input,
                        f"Enter a network interface to run your scan \n{valid_interfaces} ",
                    )
                    step += 1
                    continue

                cidr = self.get_cidr()
                state["subnet"] = f"{state['resume_ip']}/{cidr}"
                result = {
                    "subnet": state["subnet"],
                    "action": "resume",
                    "output": state["output"],
                    "interface": state["interface"],
                }
                self.domain_variables = result
                return result

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise
            except Exception as error:
                self.print_error_message(
                    message="An error occurred", exception_error=error
                )

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

            except (BackToMainMenu, BackToPreviousMenu):
                self.print_warning_message("You are already at Main Menu (Menu 1).")
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
                # [Fix] Corrected typo: user_iput → user_input
                user_input = get_user_input(input_text)
                if validator_func(user_input):
                    break
                else:
                    raise ValueError(error_text)
            except ValueError as error:
                self.print_error_message(exception_error=error)
        return user_input

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

        except (BackToMainMenu, BackToPreviousMenu):
            self.domain_variables = ""
            raise
        except Exception as error:
            error_msg = f"Error in {test_domain} domain: {str(error)}"
            self.print_error_message(
                message=f"Error in {test_domain} domain",
                exception_error=error)

            raise DomainError(error_msg) from error


class DomainError(Exception):
    """Custom exception for domain-related errors"""
    pass
