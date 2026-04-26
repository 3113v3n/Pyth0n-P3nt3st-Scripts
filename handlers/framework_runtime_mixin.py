"""Runtime loops and exit prompt helpers for PentestFramework."""

from __future__ import annotations

import sys
import termios
import time

from utils.shared.colors import Bcolors


class FrameworkRuntimeMixin:
    """Interactive and argument-driven runtime loops."""

    @staticmethod
    def get_user_input_() -> str:
        """Get user input for program exit."""

        def flush_input_output():
            """Flush any pending input and output."""
            try:
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
            except (ImportError, AttributeError):
                pass
            finally:
                sys.stdout.flush()

        while True:
            try:
                flush_input_output()
                time.sleep(0.1)

                choice = input(
                    f"\n[*] Would you like to {Bcolors.WARNING}EXIT the program{Bcolors.ENDC} "
                    f"{Bcolors.BOLD}('y' | 'n') ?{Bcolors.ENDC} "
                ).strip().lower()
                if choice in {"y", "yes", "n", "no"}:
                    return choice
            except EOFError:
                continue
            except KeyboardInterrupt:
                return "y"

    def run_program(self) -> None:
        """Main program loop."""
        while not self.exit_menu:
            try:
                # Refactor note: state reset happens once per menu iteration.
                self.reset_class_states()

                user = self.classes["user"]
                test_domain = user.get_user_domain()

                if not self.check_packages(test_domain):
                    self.print_info_message(
                        "Required packages are missing. Installing them..."
                    )
                    continue

                self.ensure_ai_ready()
                user.set_domain_variables(test_domain)
                self.process_domain(test_domain)

                valid_user_choices = {"yes", "y", "no", "n"}
                while True:
                    exit_request = self.get_user_input_()
                    if exit_request in valid_user_choices:
                        break
                    self.print_warning_message("Invalid choice. Please enter 'y' or 'n':")

                if exit_request in {"yes", "y"}:
                    self.exit_menu = True
                else:
                    self.classes["command"].clear_screen()

            except KeyboardInterrupt:
                self.print_error_message("Program interrupted by user")
                self.exit_menu = True
            except Exception as error:
                self.print_error_message(
                    message="An error in Main Program occurred",
                    exception_error=error,
                )
            finally:
                command = self.classes.get("command") if isinstance(self.classes, dict) else None
                if command:
                    command.cleanup_runtime_tmp()

    def run_program_interactively(self, user_data: dict) -> None:
        """Run an Interactive version of the program."""
        try:
            # CLI mode uses one-shot execution with shared plumbing from interactive mode.
            self.reset_class_states()
            user = self.classes["user"]
            test_domain = user_data.get("module")

            self.cmd_args = user_data.get("use_args")
            user.update_output_directory(test_domain)

            if not self.check_packages(test_domain):
                self.print_info_message(
                    "Required packages are missing. Installing them..."
                )
                return

            self.ensure_ai_ready()
            self.process_domain(test_domain, user_data=user_data)

        except KeyboardInterrupt:
            self.print_error_message("Program interrupted by user")
            self.exit_menu = True
        except Exception as error:
            self.print_error_message(
                message="An error in Main Program occurred",
                exception_error=error,
            )
        finally:
            command = self.classes.get("command") if isinstance(self.classes, dict) else None
            if command:
                command.cleanup_runtime_tmp()
