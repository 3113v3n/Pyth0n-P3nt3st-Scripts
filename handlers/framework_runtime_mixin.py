"""Runtime loops and exit prompt helpers for PentestFramework."""

from __future__ import annotations

import sys
import termios
import time
import textwrap
from pathlib import Path

from handlers.navigation import BackToMainMenu, sanitize_dialog_input
from utils.shared.colors import Bcolors
from utils.shared.commands import Commands


class FrameworkRuntimeMixin:
    """Interactive and argument-driven runtime loops."""

    @staticmethod
    def get_user_input_() -> str:
        """Get user input for program exit."""

        def flush_input_output():
            """Flush any pending input and output."""
            try:
                termios.tcflush(sys.stdin, termios.TCIFLUSH)
            except (ImportError, AttributeError, OSError, termios.error):
                pass
            finally:
                sys.stdout.flush()

        while True:
            try:
                flush_input_output()
                time.sleep(0.1)
                print(
                    f"\n{Bcolors.MUTED}[Navigation] Up/Down=history | Ctrl+C=exit gracefully{Bcolors.ENDC}"
                )

                choice = input(
                    f"\n[*] Would you like to {Bcolors.WARNING}EXIT the program{Bcolors.ENDC} "
                    f"{Bcolors.BOLD}('Y' | 'n', default: Y) ?{Bcolors.ENDC} "
                )
                choice = sanitize_dialog_input(choice).lower()
                if not choice:
                    return "y"
                if choice in {"y", "yes", "n", "no"}:
                    return choice
            except EOFError:
                # No stdin available (non-interactive run), treat as exit.
                return "y"
            except KeyboardInterrupt:
                return "y"

    @staticmethod
    def _module_output_dir(module: str) -> str:
        """Return module-specific output directory under output_directory/."""
        module_map = {
            "internal": "output_directory/Internal",
            "external": "output_directory/External",
            "mobile": "output_directory/Mobile",
            "password": "output_directory/Password",
            "va": "output_directory/Vulnerability-Assessment",
        }
        return module_map.get(module, "output_directory")

    @staticmethod
    def _to_display_path(path: Path, root: Path) -> str:
        """Return a stable, user-friendly relative path when possible."""
        try:
            return str(path.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(path)

    def _collect_space_recovery_paths(
        self,
        module: str,
        run_started_at: float,
    ) -> list[str]:
        """Collect safe-to-delete runtime/output artifacts for user guidance."""
        workspace_root = Path.cwd()
        candidates: list[str] = []
        seen: set[str] = set()
        max_recent_files = 6

        def add_candidate(path_text: str) -> None:
            if path_text in seen:
                return
            seen.add(path_text)
            candidates.append(path_text)

        def add_wildcard_if_nonempty(base_dir: Path, wildcard_text: str) -> None:
            if not base_dir.exists() or not base_dir.is_dir():
                return
            try:
                if not any(base_dir.iterdir()):
                    return
            except OSError:
                return
            add_candidate(wildcard_text)

        tmp_dir = workspace_root / ".tmp"
        output_root_dir = workspace_root / "output_directory"
        module_output_dir = workspace_root / self._module_output_dir(module)
        test_data_dir = workspace_root / "test-data"

        add_wildcard_if_nonempty(tmp_dir, ".tmp/*")
        add_wildcard_if_nonempty(output_root_dir, "output_directory/*")
        add_wildcard_if_nonempty(module_output_dir, f"{self._module_output_dir(module)}/*")
        add_wildcard_if_nonempty(test_data_dir, "test-data/*")

        scan_roots = [tmp_dir, module_output_dir]
        recent_files: list[tuple[float, str]] = []
        for root in scan_roots:
            if not root.exists() or not root.is_dir():
                continue
            for artifact in root.rglob("*"):
                if not artifact.is_file():
                    continue
                try:
                    stat_info = artifact.stat()
                except OSError:
                    continue
                if stat_info.st_mtime < (run_started_at - 1):
                    continue
                display_path = self._to_display_path(artifact, workspace_root)
                if display_path in seen:
                    continue
                recent_files.append((stat_info.st_mtime, display_path))

        recent_files.sort(key=lambda item: item[0], reverse=True)
        for _, item in recent_files[:max_recent_files]:
            add_candidate(item)

        return candidates

    def _print_space_recovery_hint(self, module: str, run_started_at: float) -> None:
        """Print a boxed post-run summary of disposable files/folders."""
        cleanup_paths = self._collect_space_recovery_paths(module, run_started_at)
        if not cleanup_paths:
            return

        border_width = 77
        body_width = border_width - 6
        border = "*" * border_width
        spacer = f"** {'':<{body_width}} **"

        print("\n" + border)
        print(border)
        print(spacer)

        header = (
            "To free up space, you can delete the following files/folders "
            "(if no longer needed):"
        )
        for line in textwrap.wrap(header, width=body_width):
            print(f"**  {line:<{body_width}}**")

        print(spacer)
        for entry in cleanup_paths:
            for line in textwrap.wrap(f"- {entry}", width=body_width):
                print(f"**  {line:<{body_width}}**")
        print(spacer)
        print(border)
        print(border)

    def run_program(self) -> None:
        """Main program loop."""
        if not sys.stdin.isatty():
            self.print_error_message(
                "Interactive mode requires a TTY. Run with '-M cli_args ...' in non-interactive environments."
            )
            self.exit_menu = True
            return

        while not self.exit_menu:
            run_started_at = time.time()
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
                self._print_space_recovery_hint(test_domain, run_started_at)

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
            except BackToMainMenu:
                self.print_info_message("Returned to Main Menu.")
                self.classes["command"].clear_screen()
                continue
            except EOFError:
                self.print_error_message(
                    "Interactive input stream closed. Exiting program."
                )
                self.exit_menu = True
            except Exception as error:
                self.print_error_message(
                    message="An error in Main Program occurred",
                    exception_error=error,
                )
            finally:
                Commands.reset_temporary_relaxation()
                command = self.classes.get("command") if isinstance(self.classes, dict) else None
                if command:
                    command.cleanup_runtime_tmp()

    def run_program_interactively(self, user_data: dict) -> None:
        """Run an Interactive version of the program."""
        try:
            run_started_at = time.time()
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
            self._print_space_recovery_hint(test_domain, run_started_at)

        except KeyboardInterrupt:
            self.print_error_message("Program interrupted by user")
            self.exit_menu = True
        except Exception as error:
            self.print_error_message(
                message="An error in Main Program occurred",
                exception_error=error,
            )
        finally:
            Commands.reset_temporary_relaxation()
            command = self.classes.get("command") if isinstance(self.classes, dict) else None
            if command:
                command.cleanup_runtime_tmp()
