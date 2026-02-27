"""
commands.py — Shared OS / subprocess utilities for the pentest framework.

All commands that accept external or user-derived inputs use shell=False (list
form) to prevent shell injection.  The private _execute_shell_string() helper
is reserved for *internal*, constant shell pipelines (e.g. mobile grep chains)
where shell=True is unavoidable; it must never receive un-sanitised user input.
"""

import os
import re
import sys
import time
import psutil
import asyncio
import aioping
import platform
import subprocess
from typing import Optional


# [Security] Characters that are meaningful to the shell and must never appear
# in inputs passed to _execute_shell_string().
_SHELL_METACHARACTERS = re.compile(r'[;&|`$<>\\!{}()\[\]]')


class Commands:
    """Shared command-execution helpers used across all framework modules."""

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    @staticmethod
    def kill_processes() -> None:
        """Terminate all child processes spawned by the current process."""
        current_process = psutil.Process()
        for child in current_process.children(recursive=True):
            try:
                child.terminate()
            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                pass

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    @staticmethod
    def execute_command(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
        """Execute an external command safely using a list of arguments.

        Uses shell=False so no shell expansion or injection is possible.

        Args:
            cmd:    Command and arguments as a list, e.g. ["nmap", "-sV", target].
            kwargs: Additional keyword arguments forwarded to subprocess.run().

        Returns:
            CompletedProcess instance with stdout, stderr and returncode.

        Raises:
            ValueError: If cmd is not a list (rejects raw shell strings).
        """
        # [Security] Enforce list form to prevent shell injection.
        if not isinstance(cmd, list):
            raise ValueError(
                "execute_command() requires a list, not a string. "
                "Use _execute_shell_string() only for internal pipelines."
            )
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            text=True,
            **kwargs,
        )
        return result

    @staticmethod
    def _execute_shell_string(command: str, **kwargs) -> subprocess.CompletedProcess:
        """Execute a shell *string* command (shell=True).

        WARNING: This method is intentionally private. It must only be called
        with *constant* internal commands (e.g. tool pipelines built from
        trusted tool names and validated file paths). Never pass raw user input
        here — use execute_command() instead.

        Args:
            command: Shell command string. Must not contain un-sanitised input.
            kwargs:  Additional keyword arguments forwarded to subprocess.run().

        Returns:
            CompletedProcess instance.
        """
        # [Security] Kept for internal shell pipelines (rabin2|grep, apktool, etc.)
        # Callers are responsible for validating all embedded paths/values.
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            **kwargs,
        )
        return result

    def run_os_commands(self, command, **kwargs) -> subprocess.CompletedProcess:
        """Backward-compatible wrapper — delegates to execute_command() for lists
        and _execute_shell_string() for strings.

        New code should call execute_command() or _execute_shell_string() directly.

        Args:
            command: Either a list[str] (safe) or a shell string (internal only).
            kwargs:  Forwarded to the underlying subprocess call.

        Returns:
            CompletedProcess instance.
        """
        if isinstance(command, list):
            return self.execute_command(command, **kwargs)
        return self._execute_shell_string(command, **kwargs)

    @staticmethod
    def run_nxc_command(cmd: list[str]) -> subprocess.Popen:
        """Stream output from NetExec (nxc) using a list-form command.

        Args:
            cmd: nxc command as a list, e.g. ["nxc", "smb", "10.0.0.1", ...].

        Returns:
            Popen instance with stdout available for line-by-line reading.
        """
        # [Security] List form — no shell expansion.
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
        )

    @staticmethod
    def run_git_cmd(git_command: list[str]) -> bool:
        """Run a git command and return True on success, False on failure.

        Args:
            git_command: git command as a list, e.g. ["git", "clone", url, path].

        Returns:
            True if the command succeeded, False otherwise.
        """
        try:
            print(f"Running command:\n{' '.join(git_command)}\n")
            subprocess.run(git_command, check=True, shell=False)
            print("Command completed successfully.")
            return True
        except subprocess.CalledProcessError as error:
            print(f"Command failed: {error}")
            return False

    @staticmethod
    def get_process_output(command: list[str]) -> str:
        """Run a command and return its combined stdout as a string.

        Args:
            command: Command as a list (avoids shell injection).

        Returns:
            Output string from the command.
        """
        # [Security] List form avoids subprocess.getoutput() which uses shell=True.
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
        )
        return result.stdout

    @staticmethod
    def auto_enter_commands(command: list[str]) -> None:
        """Spawn a subprocess and automatically send an Enter keystroke to it.

        Useful for interactive tools that pause for confirmation.

        Args:
            command: Command as a list.
        """
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                shell=False,
            )
            proc.communicate(b"\n")  # Simulate pressing Enter
        except (TypeError, OSError) as error:
            print(f"auto_enter_commands failed: {error}")

    # ------------------------------------------------------------------
    # Network utilities
    # ------------------------------------------------------------------

    @staticmethod
    def ping_hosts(host: str) -> bool:
        """Return True if the host responds to a single ICMP ping.

        Args:
            host: IP address or hostname to ping.

        Returns:
            True if host is reachable, False otherwise.
        """
        # [Security] Host is a list element — no shell injection possible.
        param = "-n" if platform.system().lower() == "windows" else "-c"
        command = ["ping", param, "1", host]
        try:
            subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
                shell=False,
            )
            return True
        except subprocess.CalledProcessError:
            return False
        except Exception as error:
            print(error)
            return False

    @staticmethod
    async def async_host_ping(ip: str) -> bool:
        """Asynchronously ping a single host.

        Args:
            ip: Target IP address.

        Returns:
            True if reachable within the 500 ms timeout.
        """
        try:
            await aioping.ping(ip, timeout=0.5)
            return True
        except Exception:
            return False

    def start_async_ping(self, ip: str) -> bool:
        """Run async_host_ping() in a new event loop from a synchronous context.

        Args:
            ip: Target IP address.

        Returns:
            True if the host responded.
        """
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            is_alive = loop.run_until_complete(self.async_host_ping(ip))
            loop.close()
            return is_alive
        except Exception as error:
            print(f"Async ping failed for {ip}: {error}")
            return False

    # ------------------------------------------------------------------
    # System utilities
    # ------------------------------------------------------------------

    @staticmethod
    def flush_system(*args) -> None:
        """Flush stdout (and optionally stdin).

        Args:
            args: Pass any truthy value to also flush stdin.
        """
        if args:
            sys.stdout.flush()
            sys.stdin.flush()
        else:
            sys.stdout.flush()
            time.sleep(0.1)

    @staticmethod
    def clear_screen() -> int:
        """Clear the terminal screen.

        Returns:
            Exit code from the system clear/cls command.
        """
        # [Security] Constant string — no user input involved.
        return os.system("cls" if os.name == "nt" else "clear")


def validate_shell_input(value: str) -> Optional[str]:
    """Verify that a string contains no shell metacharacters.

    Use this to sanitise file paths or names before embedding them in
    shell-string commands passed to _execute_shell_string().

    Args:
        value: The string to validate.

    Returns:
        The original value if safe, or None if dangerous characters are found.
    """
    if _SHELL_METACHARACTERS.search(value):
        return None
    return value
