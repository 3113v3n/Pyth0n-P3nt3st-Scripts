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
import asyncio
import threading
import platform
import subprocess
import shutil
from contextlib import contextmanager
from pathlib import Path
from typing import Optional, TextIO

try:
    import psutil
except ModuleNotFoundError:  # Optional dependency in restricted envs.
    psutil = None

try:
    import aioping
except ModuleNotFoundError:  # Optional dependency; fallback to system ping.
    aioping = None


# [Security] Characters that are meaningful to the shell and must never appear
# in inputs passed to _execute_shell_string().
_SHELL_METACHARACTERS = re.compile(r'[;&|`$<>\\!{}()\[\]]')
_ANSI_ESCAPE_RE = re.compile(
    r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
)
_THREAD_LOCAL = threading.local()


def _env_flag(name: str, default: bool) -> bool:
    """Parse boolean-like environment variables."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off"}


class StrictModeViolation(RuntimeError):
    """Raised when strict project mode blocks a risky operation."""


class Commands:
    """Shared command-execution helpers used across all framework modules."""

    _POLICY_LOCK = threading.RLock()
    _PROJECT_ROOT = Path(__file__).resolve().parents[2]
    _STRICT_PROJECT_MODE = _env_flag("PENTEST_STRICT_PROJECT_MODE", True)
    _STRICT_UMASK_PREVIOUS: int | None = None
    _RELAX_DEPTH = 0
    _BLOCKED_STRICT_EXECUTABLES = {"sudo"}
    _BLOCKED_PACKAGE_MANAGER_SUBCOMMANDS = {
        "apt": {"install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove"},
        "apt-get": {"install", "remove", "purge", "upgrade", "dist-upgrade", "full-upgrade", "autoremove"},
        "yum": {"install", "remove", "upgrade"},
        "dnf": {"install", "remove", "upgrade"},
        "pacman": {"-s", "-r", "-u", "--sync", "--remove", "--upgrade"},
        "zypper": {"install", "remove", "update", "patch", "dist-upgrade"},
        "brew": {"install", "reinstall", "upgrade", "tap", "untap"},
        "port": {"install", "uninstall", "upgrade", "selfupdate"},
        "snap": {"install", "remove", "refresh"},
        "winget": {"install", "uninstall", "upgrade"},
        "choco": {"install", "uninstall", "upgrade"},
    }

    @classmethod
    def configure_policy(
        cls,
        *,
        strict_project_mode: bool | None = None,
        project_root: str | Path | None = None,
    ) -> None:
        """Configure strict-mode policy and project root boundaries."""
        with cls._POLICY_LOCK:
            if project_root is not None:
                cls._PROJECT_ROOT = Path(project_root).resolve()
            if strict_project_mode is not None:
                cls._STRICT_PROJECT_MODE = bool(strict_project_mode)
            cls._apply_umask_locked()

    @classmethod
    def strict_project_mode_enabled(cls) -> bool:
        """Return True when strict project mode is enabled."""
        return cls._STRICT_PROJECT_MODE

    @classmethod
    def strict_policy_active(cls) -> bool:
        """Return True when strict mode is enabled and not temporarily relaxed."""
        with cls._POLICY_LOCK:
            return cls._STRICT_PROJECT_MODE and cls._RELAX_DEPTH == 0

    @classmethod
    def reset_temporary_relaxation(cls) -> None:
        """Force any temporary relaxation state back to strict defaults."""
        with cls._POLICY_LOCK:
            cls._RELAX_DEPTH = 0
            cls._apply_umask_locked()

    @classmethod
    @contextmanager
    def temporary_relaxation(cls, reason: str = ""):
        """Temporarily relax strict policy and auto-restore on exit."""
        _ = reason  # retained for logging hooks/future auditing
        with cls._POLICY_LOCK:
            cls._RELAX_DEPTH += 1
            cls._apply_umask_locked()
        try:
            yield
        finally:
            with cls._POLICY_LOCK:
                cls._RELAX_DEPTH = max(0, cls._RELAX_DEPTH - 1)
                cls._apply_umask_locked()

    @classmethod
    def _apply_umask_locked(cls) -> None:
        """Set restrictive umask in strict mode and restore when disabled."""
        strict_active = cls._STRICT_PROJECT_MODE and cls._RELAX_DEPTH == 0
        if strict_active:
            if cls._STRICT_UMASK_PREVIOUS is None:
                cls._STRICT_UMASK_PREVIOUS = os.umask(0o077)
            return
        if cls._STRICT_UMASK_PREVIOUS is not None:
            os.umask(cls._STRICT_UMASK_PREVIOUS)
            cls._STRICT_UMASK_PREVIOUS = None

    @classmethod
    def _is_within_project_root(cls, path: Path) -> bool:
        """Return True when *path* resolves inside configured project root."""
        try:
            path.resolve().relative_to(cls._PROJECT_ROOT.resolve())
            return True
        except ValueError:
            return False

    @classmethod
    def _guard_command_policy(cls, cmd: list[str]) -> None:
        """Block risky commands in strict project mode."""
        if not cls.strict_policy_active():
            return
        if not cmd:
            raise ValueError("Command list cannot be empty.")

        executable = Path(str(cmd[0])).name.lower()
        if executable in cls._BLOCKED_STRICT_EXECUTABLES:
            raise StrictModeViolation(
                f"Strict project mode blocked host-level command '{executable}'. "
                "Temporarily relax policy to run this phase if explicitly required."
            )
        blocked_tokens = cls._BLOCKED_PACKAGE_MANAGER_SUBCOMMANDS.get(executable, set())
        normalized_args = {str(part).strip().lower() for part in cmd[1:]}
        if blocked_tokens.intersection(normalized_args):
            raise StrictModeViolation(
                f"Strict project mode blocked package-manager mutation via '{executable}'. "
                "Dependency installation is disabled unless temporarily relaxed."
            )

    @staticmethod
    def _open_secure_output_file(
        path: Path,
        *,
        append: bool = False,
        encoding: str = "utf-8",
    ) -> TextIO:
        """Open output files with 0600 permissions and symlink protection."""
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_symlink():
            raise ValueError(f"Refusing to write via symlink path: {path}")

        if hasattr(os, "O_NOFOLLOW"):
            flags = os.O_WRONLY | os.O_CREAT
            flags |= os.O_APPEND if append else os.O_TRUNC
            flags |= os.O_NOFOLLOW
            fd = os.open(path, flags, 0o600)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return os.fdopen(fd, "a" if append else "w", encoding=encoding)

        handle = path.open("a" if append else "w", encoding=encoding)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return handle

    @staticmethod
    def strip_ansi(text: str) -> str:
        """Remove ANSI escape sequences from text for clean file persistence."""
        return _ANSI_ESCAPE_RE.sub("", text)

    @staticmethod
    def _with_project_tmp_env(env: dict | None = None) -> dict:
        """Return subprocess env forcing temporary files into project-local .tmp."""
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)

        tmp_root = Path.cwd() / ".tmp" / "runtime"
        tmp_root.mkdir(parents=True, exist_ok=True)
        tmp_path = str(tmp_root)
        merged_env["TMPDIR"] = tmp_path
        merged_env["TMP"] = tmp_path
        merged_env["TEMP"] = tmp_path
        return merged_env

    @staticmethod
    def cleanup_runtime_tmp() -> None:
        """Best-effort cleanup of project-local subprocess temp artifacts."""
        tmp_root = Path.cwd() / ".tmp" / "runtime"
        if not tmp_root.exists():
            return
        for child in tmp_root.iterdir():
            try:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
            except OSError:
                continue
        try:
            tmp_root.rmdir()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Process management
    # ------------------------------------------------------------------

    @staticmethod
    def kill_processes() -> None:
        """Terminate all child processes spawned by the current process."""
        if psutil is None:
            return

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
        Commands._guard_command_policy(cmd)
        env = Commands._with_project_tmp_env(kwargs.pop("env", None))
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            text=True,
            env=env,
            **kwargs,
        )
        return result

    @staticmethod
    def stream_command(
        cmd: list[str],
        *,
        output_file: str | Path | None = None,
        append: bool = False,
        prefix: str | None = None,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Run a command and stream combined stdout/stderr while optionally saving it.

        Uses shell=False and list-form commands only. The returned
        CompletedProcess contains the streamed output in stdout so callers that
        previously inspected captured stdout can keep doing so.
        """
        if not isinstance(cmd, list):
            raise ValueError("stream_command() requires a list, not a string.")
        Commands._guard_command_policy(cmd)

        user_stdout = kwargs.pop("stdout", None)
        user_stderr = kwargs.pop("stderr", None)
        if user_stdout is not None or user_stderr is not None:
            raise ValueError("stream_command() manages stdout/stderr internally.")

        file_handle: TextIO | None = None
        if output_file is not None:
            file_path = Path(output_file).expanduser()
            if not file_path.is_absolute():
                file_path = (Path.cwd() / file_path).resolve()
            if Commands.strict_policy_active() and not Commands._is_within_project_root(file_path):
                raise StrictModeViolation(
                    f"Strict project mode blocked write outside project root: {file_path}"
                )
            file_handle = Commands._open_secure_output_file(file_path, append=append)

        env = Commands._with_project_tmp_env(kwargs.pop("env", None))
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
            bufsize=1,
            env=env,
            **kwargs,
        )

        captured: list[str] = []
        try:
            assert process.stdout is not None
            for line in process.stdout:
                captured.append(line)
                text = f"{prefix}{line}" if prefix else line
                print(text, end="", flush=True)
                if file_handle is not None:
                    file_handle.write(Commands.strip_ansi(line))
                    file_handle.flush()
            returncode = process.wait()
        finally:
            if file_handle is not None:
                file_handle.close()

        return subprocess.CompletedProcess(cmd, returncode, stdout="".join(captured), stderr="")

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
        if Commands.strict_policy_active():
            raise StrictModeViolation(
                "Strict project mode blocks shell-string execution. "
                "Use list-form commands or temporarily relax policy."
            )
        # [Security] Kept for internal shell pipelines (rabin2|grep, apktool, etc.)
        # Callers are responsible for validating all embedded paths/values.
        env = Commands._with_project_tmp_env(kwargs.pop("env", None))
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            text=True,
            env=env,
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
        allow_shell_string = bool(kwargs.pop("allow_shell_string", False))
        if isinstance(command, list):
            return self.execute_command(command, **kwargs)
        if not allow_shell_string:
            raise ValueError(
                "String commands are disabled by default for security. "
                "Use list-form commands or pass allow_shell_string=True for trusted internal commands."
            )
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
        Commands._guard_command_policy(cmd)
        env = Commands._with_project_tmp_env()
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
            env=env,
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
            subprocess.run(
                git_command,
                check=True,
                shell=False,
                env=Commands._with_project_tmp_env(),
            )
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
        Commands._guard_command_policy(command)
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=False,
            text=True,
            env=Commands._with_project_tmp_env(),
        )
        return result.stdout

    @staticmethod
    def auto_enter_commands(command: list[str]) -> None:
        """Spawn a subprocess and automatically send an Enter keystroke to it.

        Useful for interactive tools that pause for confirmation.

        Args:
            command: Command as a list.
        """
        Commands._guard_command_policy(command)
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                shell=False,
                env=Commands._with_project_tmp_env(),
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
        if aioping is None:
            return Commands.ping_hosts(ip)

        try:
            await aioping.ping(ip, timeout=0.5)
            return True
        except Exception:
            return False

    def start_async_ping(self, ip: str) -> bool:
        """Run async_host_ping() from synchronous code using a thread-local event loop.

        Args:
            ip: Target IP address.

        Returns:
            True if the host responded.
        """
        if aioping is None:
            # Fallback for environments where aioping is not installed.
            return self.ping_hosts(ip)

        try:
            loop = getattr(_THREAD_LOCAL, "event_loop", None)
            if loop is None or loop.is_closed():
                loop = asyncio.new_event_loop()
                _THREAD_LOCAL.event_loop = loop
            is_alive = loop.run_until_complete(self.async_host_ping(ip))
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
        try:
            from handlers.screen import ScreenHandler
            ScreenHandler.note_screen_cleared()
        except Exception:
            pass
        # [Security] Constant string — no user input involved.
        return os.system("cls" if os.name == "nt" else "clear")


# Initialize policy defaults once at import time.
Commands.configure_policy()


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
