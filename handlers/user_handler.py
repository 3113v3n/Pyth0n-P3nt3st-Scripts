# trunk-ignore-all(black)
from __future__ import annotations

from collections.abc import Callable

from handlers.helper_handler import HelpHandler
from handlers.navigation import BackToMainMenu, BackToPreviousMenu
from handlers.opentui_menu import (
    build_menu_options,
    ensure_opentui_menu_enabled,
    run_opentui_menu,
)
from handlers.screen import ScreenHandler
from handlers.user_flow_mixin import UserFlowMixin
from utils.shared import Config, DomainError


class UserHandler(UserFlowMixin, Config, ScreenHandler):
    """Handle interactive user flows and domain dispatch."""

    MENU_DESCRIPTIONS = {
        "mobile": "APK/IPA static triage, secrets, URLs, and taxonomy-assisted findings",
        "internal": "Internal host discovery, resumable scans, and interface-aware workflows",
        "external": "Recon, screenshots, takeover checks, probing, ports, and nuclei phases",
        "va": "Nessus/Rapid7 import, filtering, and executive vulnerability reporting",
        "password": "Password list generation and credential testing against supported protocols",
        "exit": "Close the framework",
        "help": "Show the quick-start guide and module usage examples",
    }
    MENU_META = {
        "mobile": "Mobile application assessment",
        "internal": "Internal network operations",
        "external": "External attack surface mapping",
        "va": "Report triage and vulnerability analysis",
        "password": "Credential and password workflows",
        "exit": "Leave the framework",
        "help": "Operator quick-start",
    }

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
            f"\n{self.BOLD}{self.HIGHLIGHT}Pyth0n-P3nt3st-Scripts{self.ENDC}\n"
            f"{self.MUTED}Choose a workflow to begin. Type 'help' for the guided overview.{self.ENDC}\n"
            f"{self.OPTIONS}\n"
            f"[Type '{self.BOLD}help{self.ENDC}' for info, or a number to choose a test domain]...\n "
        )

    def reset_state(self) -> None:
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
        test_options = []
        for number, option in enumerate(self.test_domains, start=1):
            formatted_option = (
                f"\n{number}. {self.HIGHLIGHT}{option['domain']:<30} {self.ENDC}"
                f"[{self.INFO} ENTER {number:<2}{self.ENDC}] {option['icon']}\n"
            )
            test_options.append(formatted_option)
            self.default_test_domains.append(option["alias"])
        return "".join(test_options)

    @staticmethod
    def _helper_viewer_title(helper_function: Callable, helper_text: str | None = None) -> str:
        helper_name = getattr(helper_function, "__name__", "helper")
        if helper_name == "mobile_helper":
            return "Mobile Helper"
        if helper_name == "external_helper":
            return "External Helper"
        if helper_name == "vulnerability_helper":
            return "Vulnerability Analysis Helper"
        if helper_name == "main_program_helper":
            return "Help Center"
        if helper_name == "internal_helper":
            return "Internal Scanner Helper" if helper_text == "scanner" else "Password Module Helper"
        return "Workflow Helper"

    def start_domain_helper(self, helper_function: Callable, **kwargs):
        helper_text_key = kwargs.get("helper_text")
        if helper_text_key:
            helper_text = helper_function(helper_text_key)
        else:
            helper_text = helper_function()

        if helper_text:
            self.show_text_viewer(
                title=self._helper_viewer_title(helper_function, helper_text_key),
                prompt="Review the workflow guidance before continuing.",
                body=helper_text,
                subtitle="Module helper and operating notes",
            )

        try:
            response = self.prompt_for_choice(
                title="Start",
                prompt="Would you like to start this workflow?",
                choices=[
                    {
                        "value": "yes",
                        "label": "Start Workflow",
                        "description": "Continue into the selected assessment flow.",
                        "aliases": ("y",),
                    },
                    {
                        "value": "no",
                        "label": "Return to Main Menu",
                        "description": "Cancel this workflow and go back to the main menu.",
                        "aliases": ("n",),
                    },
                ],
                default="yes",
                footer="↑/↓ or j/k navigate • Enter confirms • Esc returns to the main menu",
            )
        except BackToPreviousMenu as error:
            raise BackToMainMenu() from error

        if response in {"yes", "y"}:
            self.command_.clear_screen()
            return
        raise BackToMainMenu()

    def _build_main_menu_options(self):
        options = build_menu_options(
            self.test_domains,
            label_getter=lambda option, _index: (
                f"{option.get('icon', '').strip()} {option['domain']}".strip()
            ),
            value_getter=lambda option, _index: option["alias"],
            description_getter=lambda option, _index: self.MENU_DESCRIPTIONS.get(
                option["alias"], option["alias"].upper()
            ),
            badge_getter=lambda _option, index: str(index + 1),
            meta_getter=lambda option, _index: self.MENU_META.get(option["alias"], ""),
        )
        options.append(
            build_menu_options(
                [{
                    "label": "Help Center",
                    "value": "help",
                    "description": self.MENU_DESCRIPTIONS["help"],
                    "meta": self.MENU_META["help"],
                }],
                label_getter=lambda option, _index: option["label"],
                value_getter=lambda option, _index: option["value"],
                description_getter=lambda option, _index: option["description"],
                badge_getter=lambda _option, _index: "?",
                meta_getter=lambda option, _index: option.get("meta", ""),
            )[0]
        )
        return options

    def get_user_domain(self) -> str:
        """Interact with the user to gather the target test domain."""
        ensure_opentui_menu_enabled(context="the main interactive workflow menu")
        selected = run_opentui_menu(
            title="Pyth0n-P3nt3st-Scripts",
            prompt="Choose a workflow to begin. Each entry includes a quick summary.",
            options=self._build_main_menu_options(),
            footer="↑/↓ or j/k navigate • number keys jump • Enter selects • Esc redraws the main menu",
            subtitle="Guided security workflows with richer module context and keyboard-first navigation",
            cancel_raises=BackToMainMenu,
        )
        if selected is None:
            raise RuntimeError("OpenTUI main menu ended without a selection")
        self.domain = str(selected.value)
        return self.domain

    def set_domain_variables(self, test_domain: str) -> dict:
        domain_handlers = {
            "internal": self.internal_ui_handler,
            "external": self.external_ui_handler,
            "mobile": self.mobile_ui_handler,
            "va": self.va_ui_handler,
            "password": self.password_ui_handler,
            "exit": self.exit_program,
            "help": self.help_me,
        }

        try:
            if test_domain not in domain_handlers:
                raise ValueError(f"Invalid domain: {test_domain}")

            if test_domain not in {"exit", "help"}:
                self.update_output_directory(test_domain)

            handler = domain_handlers[test_domain]
            self.domain_variables = handler()

            if not self.domain_variables:
                raise ValueError(f"No variables returned for domain: {test_domain}")
            return self.domain_variables

        except (BackToMainMenu, BackToPreviousMenu):
            self.domain_variables = ""
            raise
        except Exception as error:
            error_msg = f"Error in {test_domain} domain: {str(error)}"
            self.print_error_message(
                message=f"Error in {test_domain} domain",
                exception_error=error,
            )
            raise DomainError(error_msg) from error
