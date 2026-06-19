"""Domain-specific interactive UI flows extracted from UserHandler."""

from __future__ import annotations

import sys
from collections.abc import Callable

from handlers import FileHandler
from handlers.navigation import BackToMainMenu, BackToPreviousMenu
from handlers.network_handler import NetworkHandler, get_network_interfaces
from utils.internal.scan_session import ScanSessionStore


class UserFlowMixin(FileHandler):
    def mobile_ui_handler(self):
        state = self._get_menu_state("mobile")
        self.start_domain_helper(self.helper_.mobile_helper)
        step = 0

        while True:
            try:
                if step == 0:
                    taxonomy_raw = self.prompt_for_choice(
                        title="Mobile",
                        prompt="Select taxonomy tags for the findings.",
                        choices=[
                            {
                                "value": "both",
                                "label": "Both",
                                "description": "Include MASVS and MASTG mappings in the report.",
                                "aliases": ("b",),
                            },
                            {
                                "value": "masvs",
                                "label": "MASVS",
                                "description": "Focus on MASVS control mappings only.",
                                "aliases": ("m",),
                            },
                            {
                                "value": "mastg",
                                "label": "MASTG",
                                "description": "Focus on MASTG technique mappings only.",
                                "aliases": ("t",),
                            },
                            {
                                "value": "none",
                                "label": "None",
                                "description": "Skip taxonomy mapping and keep the raw findings view.",
                                "aliases": ("n",),
                            },
                        ],
                        default="both",
                    )
                    state["taxonomy"] = (
                        taxonomy_raw if taxonomy_raw in {"none", "masvs", "mastg", "both"} else "both"
                    )
                    step += 1
                    continue

                if step == 1:
                    profile_raw = self.prompt_for_choice(
                        title="Mobile",
                        prompt="Select taxonomy profile strength.",
                        choices=[
                            {
                                "value": "balanced",
                                "label": "Balanced",
                                "description": "Recommended default with a practical signal-to-noise ratio.",
                                "aliases": ("b",),
                            },
                            {
                                "value": "strict",
                                "label": "Strict",
                                "description": "Conservative matching with fewer broad classifications.",
                                "aliases": ("s",),
                            },
                            {
                                "value": "aggressive",
                                "label": "Aggressive",
                                "description": "Broader matching to surface more possible taxonomy links.",
                                "aliases": ("a",),
                            },
                        ],
                        default="balanced",
                    )
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
                        raise FileNotFoundError(f"No APK/IPA files found in: {package_path}")

                    state["source_path"] = package_path
                    state["applications"] = applications
                    total_apps = len(applications)
                    self.print_info_message(
                        "Applications discovered in directory",
                        file_path=f"{package_path} ({total_apps} found)",
                    )

                    if total_apps == 1:
                        self.print_info_message("Only one application found; scanning that app.")
                        app = dict(applications[0])
                        app["taxonomy"] = state["taxonomy"]
                        app["taxonomy_profile"] = state["taxonomy_profile"]
                        state["scan_mode"] = "single"
                        self.domain_variables = app
                        return app

                    step += 1
                    continue

                if step == 3:
                    mode = self.prompt_for_choice(
                        title="Mobile",
                        prompt="Select scan mode for the discovered applications.",
                        choices=[
                            {
                                "value": "single",
                                "label": "Single App",
                                "description": "Choose one application from the discovered list.",
                                "aliases": ("s",),
                            },
                            {
                                "value": "all",
                                "label": "All Apps",
                                "description": "Scan every discovered APK/IPA in this directory.",
                                "aliases": ("a",),
                            },
                        ],
                        default="single",
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
                    credential_choice = self.prompt_for_choice(
                        title="Vulnerability Analysis",
                        prompt="Should the report enforce credentialed-host filtering?",
                        choices=[
                            {
                                "value": "yes",
                                "label": "Credentialed Check",
                                "description": "Default Nessus-style credentialed filtering for higher-confidence coverage.",
                                "aliases": ("y",),
                            },
                            {
                                "value": "no",
                                "label": "Uncredentialed View",
                                "description": "Analyze all findings without enforcing credentialed-host filtering.",
                                "aliases": ("n",),
                            },
                        ],
                        default="yes",
                    )
                    state["credentialed_check"] = credential_choice in {"y", "yes"}
                    step += 1
                    continue

                if step == 2:
                    file_format_index = self.create_menu_selection(
                        menu_selection=f" \n {self.WARNING} Select the file format of the Scanned File(s):{self.ENDC} \n",
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

                if step == 3:
                    state["search_dir"] = self.get_file_path(
                        "\nEnter Location Where your Scan files are located \n",
                        self.check_folder_exists,
                    )
                    step += 1
                    continue

                if step == 4:
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
                    "credentialed_check": state.get("credentialed_check", True),
                }
                self.domain_variables = result
                return result

            except BackToPreviousMenu:
                step = self._go_to_previous_step(step)
            except BackToMainMenu:
                self._clear_all_menu_state()
                raise
            except (FileExistsError, FileNotFoundError, ValueError) as error:
                self.print_error_message(message="Error in VA UI handler", exception_error=error)

    def external_ui_handler(self):
        state = self._get_menu_state("external")
        self.start_domain_helper(self.helper_.external_helper)
        from utils.external.external_constants import DEFAULT_PHASES, SAFE_OPERATOR_TAG_DEFAULT
        step = 0

        while True:
            try:
                if step == 0:
                    raw = self.get_user_input("Enter domain to enumerate (example.domain.com): ")
                    domain = raw.replace("https://", "").replace("http://", "").strip("/")
                    if not self.validate_domain(domain):
                        self.print_warning_message(f"'{raw}' is not a valid domain. Try again.")
                        continue
                    state["target_domain"] = domain
                    step += 1
                    continue

                if step == 1:
                    phases = self.prompt_for_multi_choice(
                        title="External",
                        prompt="Select the external workflow phases to run.",
                        choices=[
                            {
                                "value": phase,
                                "label": phase.replace("_", " ").title(),
                                "description": f"Include the {phase} phase in the external assessment pipeline.",
                                "meta": "Default phase order",
                            }
                            for phase in DEFAULT_PHASES
                        ],
                        default_values=DEFAULT_PHASES,
                    )
                    state["phases"] = tuple(phase for phase in phases if phase in DEFAULT_PHASES) or DEFAULT_PHASES
                    step += 1
                    continue

                if step == 2:
                    safe_mode_choice = self.prompt_for_choice(
                        title="External",
                        prompt="Enable safe mode for a lower-impact external workflow?",
                        choices=[
                            {
                                "value": "yes",
                                "label": "Safe Mode",
                                "description": "Recommended lower-impact profile with audit metadata support.",
                                "aliases": ("y",),
                            },
                            {
                                "value": "no",
                                "label": "Standard Mode",
                                "description": "Run without the additional safe-mode guardrails.",
                                "aliases": ("n",),
                            },
                        ],
                        default="yes",
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

    def password_ui_handler(self):
        state = self._get_menu_state("password")
        self.start_domain_helper(self.helper_.internal_helper, helper_text="hashfunction")
        target_text = "[-] Enter the IP address of your target [ 10.10.10.3 ] \n"
        domain_text = "[*] Enter the domain of your target [ testdomain.xy.z ] \n"
        step = 0

        while True:
            try:
                if step == 0:
                    state["action"] = self.prompt_for_choice(
                        title="Password Module",
                        prompt="Choose the password workflow to run.",
                        choices=[
                            {
                                "value": "generate",
                                "label": "Generate Password List",
                                "description": "Build a candidate list from cracked hashes and NTDS material.",
                                "aliases": ("g",),
                            },
                            {
                                "value": "test",
                                "label": "Test Credentials",
                                "description": "Use a password list against a target system and domain.",
                                "aliases": ("t",),
                            },
                        ],
                    )
                    step += 1
                    continue

                if state["action"] == "generate":
                    if step == 1:
                        state["hashes"] = self.get_file_path(
                            "\n[-] Enter full path to your cracked hashes \n",
                            self.file_exists,
                            require_file=True,
                        )
                        step += 1
                        continue
                    if step == 2:
                        state["dumps"] = self.get_file_path(
                            "\n[-] Enter full path to your dump [ntds] \n",
                            self.file_exists,
                            require_file=True,
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
                    require_file=True,
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
        state = self._get_menu_state("internal")
        self.start_domain_helper(self.helper_.internal_helper, helper_text="scanner")
        step = 0

        _nh = NetworkHandler()
        valid_interfaces = [
            iface
            for iface in get_network_interfaces()
            if _nh._is_interface_active(iface) and not iface.startswith(("br-", "docker", "veth", "lo"))
        ]
        if self.debug:
            print(f"DEBUG: Available active interfaces={valid_interfaces}")

        while True:
            try:
                if step == 0:
                    state["action"] = self.prompt_for_choice(
                        title="Internal",
                        prompt="Choose the internal network workflow.",
                        choices=[
                            {
                                "value": "scan",
                                "label": "New Scan",
                                "description": "Start a fresh host discovery run for a subnet.",
                                "aliases": ("s",),
                            },
                            {
                                "value": "resume",
                                "label": "Resume Scan",
                                "description": "Continue from a saved unresponsive-hosts artifact.",
                                "aliases": ("r",),
                            },
                        ],
                    )
                    state.pop("resume_requires_manual", None)
                    step += 1
                    continue

                if state["action"] == "scan":
                    if step == 1:
                        state["interface"] = self.prompt_for_choice(
                            title="Internal",
                            prompt="Select the active network interface for this scan.",
                            choices=[
                                {
                                    "value": interface,
                                    "label": interface,
                                    "description": "Active interface discovered on this host.",
                                }
                                for interface in valid_interfaces
                            ],
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
                    resume_ip = self.display_saved_files(self.output_directory, resume_scan=True)
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
                        matched_interface = session_store.find_similar_active_interface(saved_snapshot)
                        if not saved_subnet:
                            raise ValueError("Saved scan session has no subnet metadata for resume.")
                        if not matched_interface:
                            raise ValueError(
                                "Resume blocked: no similar active interface detected for the saved scan session."
                            )
                        state["subnet"] = saved_subnet
                        state["interface"] = matched_interface
                        self.print_info_message("Resume metadata loaded from saved scan session")
                        self.print_info_message("Using subnet", file_path=state["subnet"])
                        self.print_info_message("Using interface", file_path=state["interface"])
                        result = {
                            "subnet": state["subnet"],
                            "action": "resume",
                            "output": state["output"],
                            "interface": state["interface"],
                        }
                        self.domain_variables = result
                        return result

                    self.print_warning_message(
                        "No saved session metadata found for this file. Falling back to manual CIDR resume."
                    )
                    state["resume_requires_manual"] = True
                    step += 1
                    continue

                if step == 2:
                    state["interface"] = self.prompt_for_choice(
                        title="Internal",
                        prompt="Select the active network interface for this resumed scan.",
                        choices=[
                            {
                                "value": interface,
                                "label": interface,
                                "description": "Active interface discovered on this host.",
                            }
                            for interface in valid_interfaces
                        ],
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
                self.print_error_message(message="An error occurred", exception_error=error)

    @staticmethod
    def exit_program():
        return sys.exit(1)

    def get_user_subnet(self):
        text = "\n[+] Please provide a valid subnet [10.0.0.0/24]\n"
        error_text = " Invalid IP address format provided"
        return self.get_valid_ip_addr(self.get_user_input, text, self.validate_ip_and_cidr, error_text)

    def get_cidr(self):
        cidr = "\n[+] Please provide a valid CIDR address that you were scanning previously [0-32]\n"
        error_txt = " Invalid CIDR provided"
        return self.get_valid_ip_addr(self.get_user_input, cidr, self.validate_cidr, error_txt)

    def get_valid_ip_addr(
        self,
        get_user_input: Callable[[str], str],
        input_text: str,
        validator_func: Callable[[str], bool],
        error_text: str,
    ):
        while True:
            try:
                user_input = get_user_input(input_text)
                if validator_func(user_input):
                    break
                raise ValueError(error_text)
            except ValueError as error:
                self.print_error_message(exception_error=error)
        return user_input

    def help_me(self):
        self.show_text_viewer(
            title="Help Center",
            prompt="Framework quick-start, module usage, and CLI reference.",
            body=self.helper_.main_program_helper(),
            subtitle="Operator guide and command reference",
        )
        raise BackToMainMenu()
