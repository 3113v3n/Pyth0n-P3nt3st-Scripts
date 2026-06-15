"""
test_creds.py — Credential testing against SMB/network protocols using NetExec (nxc).

Bug fix applied:
  1. handle_string_replace() had a `return` statement inside the for-loop, causing
     it to exit after checking only the *first* word in possible_vars. The return
     is now outside the loop so all replacements are applied before returning.
  2. get_string_from_list() had the same early-return bug — fixed to check all items.
"""

import os
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path
from ..shared import Commands
from ..shared.colors import Bcolors
from .password_output import parse_credentials_from_output


class CredentialsUtil(Bcolors):
    """Test discovered credentials against a target host via SMB (or other protocols)."""

    MAX_ATTEMPTS = 2
    SUCCESS_DECORATOR = "[+]"
    LOGON_FAILURE_DECORATOR = "[-]"
    LOGON_FAILURE_TEXT = [
        "STATUS_LOGON_FAILURE",
        "STATUS_LOGON_TYPE_NOT_GRANTED",
        "STATUS_MORE_PROCESSING_REQUIRED",
        "STATUS_PASSWORD_EXPIRED",
    ]
    LOGON_SUCCESS_TEXT = ["(Pwn3d!)", "", "(nla:True)"]
    NXC_SCHEMA_MISMATCH_MARKERS = (
        "Schema mismatch detected",
        "newer version of nxc is being run on an old DB schema",
    )
    NXC_COMMAND_TIMEOUT_SECONDS = 45

    def __init__(self):
        super().__init__()
        self.creds_file = ""
        self.target = ""
        self.domain = ""
        self.log_file = "Cred_test.log"
        self._protocol = "smb"
        self.timer_delay = 5
        self.file_delimiter = ":"
        self.attempts = 0
        self.tested_accounts: dict[str, bool] = {}
        self.output_file = ""
        self.run_command = Commands()
        self._nxc_schema_mismatch_seen = False
        self._nxc_env: dict[str, str] | None = None

    @staticmethod
    def _open_private_output(path: str, append: bool = True):
        """Open credential logs/output with owner-only permissions."""
        flags = os.O_WRONLY | os.O_CREAT
        flags |= os.O_APPEND if append else os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        fd = os.open(path, flags, 0o600)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return os.fdopen(fd, "a" if append else "w", encoding="utf-8")

    def split_pass_file(self) -> dict[str, str]:
        """Parse credential file into a ``{username: password}`` dictionary.

        Supported formats:
          1. ``username:password``
          2. grouped common-password blocks written by password generate mode.
        """
        try:
            return parse_credentials_from_output(self.creds_file)
        except FileNotFoundError:
            print(f"[!] Credentials file not found: {self.creds_file}")
            return {}

    def test_credentials(
        self,
        target: str,
        domain: str,
        output_file: str,
        passlist: str,
        save_dir: str,
    ) -> None:
        """Test every credential in *passlist* against *target* via NetExec.

        Args:
            target:      IP address of the target host.
            domain:      Active Directory domain name.
            output_file: Path to write successful login lines.
            passlist:    Path to the username:password file.
            save_dir:    Directory to write the full credential test log.
        """
        self.target = target
        self.domain = domain
        self.output_file = output_file
        self.creds_file = passlist
        self._nxc_schema_mismatch_seen = False
        self._nxc_env = self._build_nxc_env(save_dir)

        user_pass_list = self.split_pass_file()
        date = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        start_message = (
            f"\nStarting credential test against {self.target} "
            f"on protocol {self._protocol} at {date}\n"
        )
        print(start_message)

        with self._open_private_output(f"{save_dir}/{self.log_file}", append=True) as log_file:
            log_file.write(f"{start_message}\n")

        if not user_pass_list:
            print("[-] No valid credentials found to test.")
            return

        for username, password in user_pass_list.items():
            if self._nxc_schema_mismatch_seen:
                break
            if username in self.tested_accounts:
                continue
            self.run_nxc(username, password, self.domain, save_dir)
            self.tested_accounts[username] = True

        if self._nxc_schema_mismatch_seen:
            print(
                "[!] NetExec SMB database schema mismatch detected. "
                "Credential testing stopped to avoid repeating the same error."
            )

    @staticmethod
    def _build_nxc_env(save_dir: str) -> dict[str, str]:
        """Use a project-local NetExec home to avoid stale user DB schemas."""
        base_dir = Path(save_dir) / ".nxc_home"
        base_dir.mkdir(parents=True, exist_ok=True)
        xdg_config = base_dir / ".config"
        xdg_data = base_dir / ".local" / "share"
        xdg_config.mkdir(parents=True, exist_ok=True)
        xdg_data.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(base_dir, 0o700)
        except OSError:
            pass
        return {
            "HOME": str(base_dir.resolve()),
            "XDG_CONFIG_HOME": str((base_dir / ".config").resolve()),
            "XDG_DATA_HOME": str((base_dir / ".local" / "share").resolve()),
        }

    def _is_nxc_schema_mismatch(self, line: str) -> bool:
        return any(marker in line for marker in self.NXC_SCHEMA_MISMATCH_MARKERS)

    def _reset_nxc_home(self) -> None:
        """Remove the module-local NetExec home after a schema mismatch."""
        if not self._nxc_env:
            return
        home = self._nxc_env.get("HOME")
        if not home:
            return
        home_path = Path(home)
        try:
            if home_path.exists() and ".nxc_home" in home_path.parts:
                shutil.rmtree(home_path, ignore_errors=True)
        except OSError:
            pass

    def run_nxc(self, user: str, passwd: str, domain: str, save_dir: str) -> None:
        """Execute a single NetExec credential test and log the result.

        Args:
            user:     Username to test.
            passwd:   Password to test.
            domain:   Target domain.
            save_dir: Directory for the log file.
        """
        # [Security] Command is a list — no shell injection possible.
        command = ["nxc", self._protocol, self.target, "-u", user, "-p", passwd]
        if domain:
            command.extend(["-d", domain])

        env = self._nxc_env or self._build_nxc_env(save_dir)

        with self._open_private_output(f"{save_dir}/{self.log_file}", append=True) as logfile:
            try:
                completed = self.run_command.run_nxc_command(
                    command,
                    env=env,
                    timeout=self.NXC_COMMAND_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as error:
                output = error.stdout or ""
                if isinstance(output, bytes):
                    output = output.decode("utf-8", errors="replace")
                for line in str(output).splitlines():
                    logfile.write(f"{line}\n")
                    print(self.format_text_output(line.strip()))
                message = (
                    f"[!] nxc timed out after {self.NXC_COMMAND_TIMEOUT_SECONDS}s "
                    f"for user '{user}' against {self.target}; continuing."
                )
                print(message)
                logfile.write(f"{message}\n")
                return

            for line in completed.stdout.splitlines():
                line = line.strip()
                if self._is_nxc_schema_mismatch(line):
                    self._nxc_schema_mismatch_seen = True
                    logfile.write(f"{line}\n")
                    print(
                        "[!] NetExec reported an SMB DB schema mismatch. "
                        "The module-local NetExec home will be reset; retry the "
                        "password test."
                    )
                    self._reset_nxc_home()
                    break

                formatted_line = self.format_text_output(line)
                print(formatted_line)

                if self.SUCCESS_DECORATOR in line:
                    with self._open_private_output(self.output_file, append=True) as success_file:
                        success_file.write(f"{line}\n")

                logfile.write(f"{line}\n")

        if completed.returncode != 0:
            if self._nxc_schema_mismatch_seen:
                return
            print(f"[!] nxc exited with error code {completed.returncode}")

    @staticmethod
    def get_string_from_list(word_list: list, sentence: str) -> bool:
        """Return True if any word in *word_list* appears in *sentence*.

        [Fix] The previous implementation had a `return` inside the for-loop,
        so it evaluated only the first word and never checked the rest. The
        return is now outside the loop.

        Args:
            word_list: List of strings to search for.
            sentence:  Text to search within.

        Returns:
            True if at least one word is found.
        """
        for word in word_list:
            if word in sentence:
                return True
        return False

    def format_text_output(self, text: str) -> str:
        """Apply ANSI color codes to a NetExec output line.

        Args:
            text: A single line of raw nxc output.

        Returns:
            The same line with color codes applied where relevant.
        """
        cleaned_line = " ".join(text.split())

        if self.LOGON_FAILURE_DECORATOR in cleaned_line and self.get_string_from_list(
            self.LOGON_FAILURE_TEXT, cleaned_line
        ):
            return self.handle_colored_text(
                cleaned_line,
                self.LOGON_FAILURE_DECORATOR,
                self.LOGON_FAILURE_TEXT,
                self.WARNING,
                self.ENDC,
                self.FAIL,
                self.handle_string_replace,
            )

        if self.SUCCESS_DECORATOR in cleaned_line and self.get_string_from_list(
            self.LOGON_SUCCESS_TEXT, cleaned_line
        ):
            return self.handle_colored_text(
                cleaned_line,
                self.SUCCESS_DECORATOR,
                self.LOGON_SUCCESS_TEXT,
                self.OKGREEN,
                self.ENDC,
                self.WARNING,
                self.handle_string_replace,
            )

        return cleaned_line

    @staticmethod
    def handle_colored_text(
        cleaned_line: str,
        decorator: str,
        text_to_colour: list,
        dec_color_start: str,
        color_end: str,
        txt_color_start: str,
        handle_string_replace: callable,
    ) -> str:
        """Wrap the decorator and matching status text in ANSI color codes.

        Args:
            cleaned_line:        The full output line with extra spaces removed.
            decorator:           The prefix marker, e.g. "[+]".
            text_to_colour:      List of status strings to highlight.
            dec_color_start:     ANSI code for decorator color.
            color_end:           ANSI reset code.
            txt_color_start:     ANSI code for status text color.
            handle_string_replace: Callback that replaces status strings with colored versions.

        Returns:
            The line with color codes applied.
        """
        parts = cleaned_line.split(decorator)
        if len(parts) > 1:
            return (
                f"{parts[0]}{dec_color_start}{decorator}{color_end} "
                f"{handle_string_replace(parts[1], text_to_colour, txt_color_start, color_end)}"
            )
        return cleaned_line

    @staticmethod
    def handle_string_replace(
        full_text: str,
        possible_vars: list,
        start_color: str,
        end_color: str,
    ) -> str:
        """Replace each word in *possible_vars* found in *full_text* with a colored version.

        [Fix] The previous implementation had a `return` statement inside the
        for-loop, so only the first match was ever returned and subsequent words
        in *possible_vars* were never checked. The return is now outside the loop
        so all replacements are applied before returning.

        Args:
            full_text:     The text to perform replacements on.
            possible_vars: List of strings to wrap in color codes.
            start_color:   ANSI opening color code.
            end_color:     ANSI reset code.

        Returns:
            The text with all occurrences of possible_vars wrapped in color codes.
        """
        sentence = full_text
        for word in possible_vars:
            if word in sentence:
                colored_word = f"{start_color}{word}{end_color}"
                sentence = sentence.replace(word, colored_word)
        # [Fix] return is now OUTSIDE the loop so all words are processed.
        return sentence
