"""Cross-platform package/dependency management for framework modules.

This handler now supports dynamic dependency checks and installation planning for:
- Debian-like Linux (apt)
- macOS (Homebrew)
- Windows (winget or chocolatey)

It also provides first-run virtualenv bootstrapping for the project.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections import defaultdict
from importlib import metadata
from pathlib import Path
from typing import Dict, List

from handlers.messages import DisplayHandler
from utils.shared import Commands, Config


class PackageHandler(Config, DisplayHandler, Commands):
    """Check, plan, and install runtime dependencies for pentest modules."""

    _SUPPORTED_OS = {"debian", "macos", "windows"}

    # Commands can differ from dependency identifiers; aliases reduce false positives.
    _COMMAND_ALIASES = {
        "netexec": ("nxc", "netexec"),
        "d2j-dex2jar": ("d2j-dex2jar", "dex2jar"),
        "httpx-toolkit": ("httpx", "httpx-toolkit"),
        "getallurls": ("gau", "getallurls"),
        "chad": ("google-chad", "chad"),
        "aquatone-discover": ("aquatone-discover", "aquatone"),
        "aquatone-scan": ("aquatone-scan", "aquatone"),
        "Gxss": ("Gxss", "gxss"),
    }

    # Optional version probes for command identity checks (prevents ambiguous matches).
    _VERSION_PROBES = {
        "netexec": {"args": ["--version"], "contains": ("nxc", "netexec")},
        "go": {"args": ["version"], "contains": ("go version",)},
        "java": {"args": ["-version"], "contains": ("version",)},
        "pipx": {"args": ["--version"], "contains": ("pipx",)},
    }

    # Tools installed via pipx (package name may differ from command id).
    _PIPX_PACKAGES = {
        "netexec": "git+https://github.com/Pennyw0rth/NetExec",
        "objection": "objection",
        "file-scraper": "file-scraper",
        "chad": "google-chad",
        "bbot": "bbot",
        "uro": "uro",
        "snallygaster": "snallygaster",
    }

    # Tools installed via `go install <module>@latest`.
    _GO_MODULES = {
        "subjs": "github.com/lc/subjs",
        "qsreplace": "github.com/tomnomnom/qsreplace",
        "gowitness": "github.com/sensepost/gowitness",
        "gauplus": "github.com/bp0lr/gauplus",
        "waybackurls": "github.com/tomnomnom/waybackurls",
        "gf": "github.com/tomnomnom/gf",
        "urlhunter": "github.com/utkusen/urlhunter",
        "Gxss": "github.com/KathanP19/Gxss",
        "subzy": "github.com/PentestPad/subzy",
        "subjack": "github.com/haccer/subjack",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei",
        "dalfox": "github.com/hahwul/dalfox/v2",
    }

    # Tools installed via RubyGems.
    _GEM_PACKAGES = {
        "aquatone-discover": "aquatone",
        "aquatone-scan": "aquatone",
    }

    # OS-specific package aliases for system package managers.
    _SYSTEM_PACKAGE_ALIASES = {
        "debian": {
            "go": "golang-go",
            "java": "default-jdk",
            "d2j-dex2jar": "dex2jar",
            "exiftool": "libimage-exiftool-perl",
            "snap": "snapd",
        },
        "macos": {
            "adb": "android-platform-tools",
            "sqlitebrowser": "db-browser-for-sqlite",
            "java": "openjdk",
            "d2j-dex2jar": "dex2jar",
        },
        "windows-winget": {
            "go": "GoLang.Go",
            "git": "Git.Git",
            "adb": "Google.PlatformTools",
            "java": "EclipseAdoptium.Temurin.17.JDK",
            "nuclei": "ProjectDiscovery.Nuclei",
            "exiftool": "OliverBetz.ExifTool",
            "ruby": "RubyInstallerTeam.Ruby.3.2",
        },
        "windows-choco": {
            "go": "golang",
            "git": "git",
            "adb": "adb",
            "java": "temurin17",
            "nuclei": "nuclei",
            "exiftool": "exiftool",
            "ruby": "ruby",
        },
    }

    def __init__(self) -> None:
        super().__init__()
        self.operating_system = platform.system().lower()
        self.os_family = self._detect_os_family()
        self.package_manager = self._detect_system_package_manager()
        self.is_supported_os = None
        self._which_cache: dict[str, str | None] = {}
        self._probe_cache: dict[tuple[str, tuple[str, ...]], bool] = {}
        self._search_path = self._build_search_path()

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.operating_system = platform.system().lower()
        self.os_family = self._detect_os_family()
        self.package_manager = self._detect_system_package_manager()
        self.is_supported_os = None
        self._which_cache = {}
        self._probe_cache = {}
        self._search_path = self._build_search_path()

    @classmethod
    def reset_class_states(cls):
        """Deprecated — use reset_state() on the instance instead."""
        cls.operating_system = platform.system().lower()
        cls.is_supported_os = None

    @classmethod
    def ensure_project_virtualenv(
        cls,
        project_root: str | Path | None = None,
        venv_name: str = ".venv",
        requirements_file: str = "requirements.txt",
    ) -> bool:
        """Ensure project-local venv exists; create/install and re-exec on first run.

        Returns:
            True when execution may continue in the current process.
            False only if bootstrapping failed and execution should proceed as-is.
        """
        if os.environ.get("PENTEST_SKIP_VENV_BOOTSTRAP") == "1":
            return True

        root = Path(project_root or Path(__file__).resolve().parents[1]).resolve()
        venv_dir = root / venv_name
        venv_python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

        try:
            current_prefix = Path(sys.prefix).resolve()
            in_project_venv = current_prefix == venv_dir or venv_dir in current_prefix.parents
        except Exception:
            in_project_venv = False

        if in_project_venv:
            return True

        if not venv_dir.exists():
            print("[Bootstrap] First run detected. Creating project virtualenv...")
            try:
                subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
                if venv_python.exists():
                    subprocess.run(
                        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"],
                        check=False,
                    )
                    req_file = root / requirements_file
                    if req_file.exists():
                        print("[Bootstrap] Installing Python requirements into project virtualenv...")
                        subprocess.run(
                            [str(venv_python), "-m", "pip", "install", "-r", str(req_file)],
                            check=True,
                        )
            except Exception as error:
                print(f"[Bootstrap] Virtualenv setup failed: {error}")
                return False

        if venv_python.exists():
            # Always continue execution from project venv for consistent dependency resolution.
            os.execv(str(venv_python), [str(venv_python), *sys.argv])

        return True

    def _detect_os_family(self) -> str:
        if self.operating_system == "linux":
            return "debian"
        if self.operating_system == "darwin":
            return "macos"
        if self.operating_system == "windows":
            return "windows"
        return "unsupported"

    def _detect_system_package_manager(self) -> str | None:
        """Detect available package manager for system dependencies."""
        if self.os_family == "debian":
            return "apt" if shutil.which("apt-get") else None
        if self.os_family == "macos":
            return "brew" if shutil.which("brew") else None
        if self.os_family == "windows":
            if shutil.which("winget"):
                return "winget"
            if shutil.which("choco"):
                return "choco"
            return None
        return None

    def _check_is_supported(self) -> bool:
        """Return True if this OS is supported for dependency automation."""
        if self.os_family not in self._SUPPORTED_OS:
            self.print_warning_message(
                f"Operating system '{self.operating_system}' is not supported for auto-installation."
            )
            return False

        if not self.package_manager:
            self.print_warning_message(
                "No system package manager detected (apt/brew/winget/choco). "
                "System-tool installation will be best-effort only."
            )
        return True

    @staticmethod
    def _is_pip_package_missing(package_name: str) -> bool:
        try:
            metadata.version(package_name)
            return False
        except metadata.PackageNotFoundError:
            return True
        except Exception:
            return True

    def _build_search_path(self) -> str:
        path_entries = os.environ.get("PATH", "").split(os.pathsep)
        extras = [
            str(Path.home() / ".local" / "bin"),
            str(Path.home() / "go" / "bin"),
            str(Path.home() / "AppData" / "Roaming" / "Python" / "Scripts"),
        ]

        merged: list[str] = []
        seen = set()
        for entry in [*path_entries, *extras]:
            cleaned = str(entry).strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            merged.append(cleaned)
        return os.pathsep.join(merged)

    def _which_cached(self, executable: str) -> str | None:
        if executable in self._which_cache:
            return self._which_cache[executable]
        resolved = shutil.which(executable, path=self._search_path)
        self._which_cache[executable] = resolved
        return resolved

    def _probe_binary_identity(self, executable_path: str, args: list[str], expected_tokens: tuple[str, ...]) -> bool:
        cache_key = (executable_path, tuple(args))
        if cache_key in self._probe_cache:
            return self._probe_cache[cache_key]

        try:
            proc = self.execute_command([executable_path, *args], timeout=5)
            output = f"{proc.stdout}\n{proc.stderr}".lower()
            result = any(token.lower() in output for token in expected_tokens)
        except Exception:
            result = False

        self._probe_cache[cache_key] = result
        return result

    def _command_candidates(self, package_name: str) -> tuple[str, ...]:
        aliases = self._COMMAND_ALIASES.get(package_name)
        if aliases:
            return aliases
        return (package_name,)

    def _binary_missing(self, package_name: str) -> bool:
        candidates = self._command_candidates(package_name)
        probe = self._VERSION_PROBES.get(package_name)

        for candidate in candidates:
            resolved = self._which_cached(candidate)
            if not resolved:
                continue
            if probe:
                if self._probe_binary_identity(
                    resolved,
                    probe.get("args", ["--version"]),
                    tuple(probe.get("contains", (candidate,))),
                ):
                    return False
                # If probe fails unexpectedly but command exists, treat as present.
                return False
            return False

        return True

    def _is_package_missing(self, package_name: str) -> bool:
        if not self.is_supported_os:
            return False

        if package_name == "anthropic":
            return self._is_pip_package_missing("anthropic")

        return self._binary_missing(package_name)

    def _extract_domain_tools(self, test_domain: str) -> list[str]:
        domain_packages = {
            "mobile": self.mobile_packages,
            "internal": self.internal_packages,
            "external": self.external_packages,
        }
        selected = domain_packages.get(test_domain)
        if not selected:
            return []

        tools: set[str] = set()
        for item in selected:
            for raw_name in item.get("name", []):
                name = str(raw_name).strip()
                if name:
                    tools.add(name)

        return sorted(tools)

    def get_missing_packages(self, test_domain: str) -> list[Dict[str, object]]:
        """Return an installation plan for dependencies missing from the active host."""
        if not self.is_supported_os:
            return []

        required_tools = self._extract_domain_tools(test_domain)
        if not required_tools:
            return []

        missing_tools = [tool for tool in required_tools if self._is_package_missing(tool)]
        if not missing_tools:
            return []

        return self._build_install_plan(missing_tools)

    def _with_privilege(self, command: list[str]) -> list[str]:
        if self.os_family in {"debian", "macos"}:
            try:
                if hasattr(os, "geteuid") and os.geteuid() != 0 and self._which_cached("sudo"):
                    return ["sudo", *command]
            except Exception:
                pass
        return command

    def _system_package_alias_key(self) -> str:
        if self.os_family != "windows":
            return self.os_family
        return "windows-winget" if self.package_manager == "winget" else "windows-choco"

    def _system_package_name(self, tool_name: str) -> str:
        alias_key = self._system_package_alias_key()
        mapping = self._SYSTEM_PACKAGE_ALIASES.get(alias_key, {})
        return mapping.get(tool_name, tool_name)

    def _build_system_install_commands(self, package_names: list[str]) -> list[list[str]]:
        if not package_names or not self.package_manager:
            return []

        if self.package_manager == "apt":
            return [self._with_privilege(["apt-get", "install", "-y", *package_names])]

        if self.package_manager == "brew":
            return [["brew", "install", *package_names]]

        if self.package_manager == "choco":
            return [["choco", "install", "-y", *package_names]]

        if self.package_manager == "winget":
            return [
                [
                    "winget",
                    "install",
                    "--exact",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    package_name,
                ]
                for package_name in package_names
            ]

        return []

    def _action(self, name: str, commands: list[list[str]], verify_names: list[str]) -> Dict[str, object]:
        return {
            "name": name,
            "commands": commands,
            "verify_names": verify_names,
        }

    def _build_install_plan(self, missing_tools: list[str]) -> list[Dict[str, object]]:
        """Build normalized installation actions from missing tool identifiers."""
        actions: list[Dict[str, object]] = []
        system_tool_to_pkg: dict[str, str] = {}

        needs_pipx = any(tool in self._PIPX_PACKAGES for tool in missing_tools)
        needs_go = any(tool in self._GO_MODULES for tool in missing_tools)
        needs_gem = any(tool in self._GEM_PACKAGES for tool in missing_tools)

        if needs_pipx and self._binary_missing("pipx"):
            actions.append(
                self._action(
                    "pipx",
                    [
                        [sys.executable, "-m", "pip", "install", "--user", "pipx"],
                        [sys.executable, "-m", "pipx", "ensurepath"],
                    ],
                    ["pipx"],
                )
            )

        if needs_go and self._binary_missing("go"):
            go_cmds = self._build_system_install_commands([self._system_package_name("go")])
            if go_cmds:
                actions.append(self._action("go", go_cmds, ["go"]))
            else:
                self.print_warning_message("'go' is missing and no package manager is available to install it.")

        if needs_gem and self._binary_missing("gem"):
            ruby_cmds = self._build_system_install_commands([self._system_package_name("ruby")])
            if ruby_cmds:
                actions.append(self._action("ruby", ruby_cmds, ["ruby", "gem"]))
            else:
                self.print_warning_message("'ruby/gem' is missing and no package manager is available to install it.")

        # Fine-grained installers (python/pipx/go/gem), then system package fallback.
        for tool in missing_tools:
            if tool == "anthropic":
                actions.append(
                    self._action(
                        "anthropic",
                        [[sys.executable, "-m", "pip", "install", "anthropic"]],
                        ["anthropic"],
                    )
                )
                continue

            if tool in self._PIPX_PACKAGES:
                package_ref = self._PIPX_PACKAGES[tool]
                # pipx is its own CLI managing isolated envs; invoke the binary
                # directly rather than `python -m pipx`, which would require pipx
                # to be importable from the (often venv-bound) interpreter.
                actions.append(
                    self._action(
                        f"pipx:{tool}",
                        [["pipx", "install", package_ref]],
                        [tool],
                    )
                )
                continue

            if tool in self._GO_MODULES:
                module = self._GO_MODULES[tool]
                actions.append(
                    self._action(
                        f"go:{tool}",
                        [["go", "install", f"{module}@latest"]],
                        [tool],
                    )
                )
                continue

            if tool in self._GEM_PACKAGES:
                gem_name = self._GEM_PACKAGES[tool]
                # System gem dirs (e.g. /Library/Ruby/Gems on macOS) need sudo,
                # and on macOS SIP also blocks the default binstub dir
                # (/usr/bin). Redirect binstubs to /usr/local/bin so the install
                # succeeds and the resulting CLI ends up on a PATH most setups
                # already pick up. `_with_privilege` is a no-op on root/Windows.
                gem_cmd = ["gem", "install"]
                if self.os_family == "macos":
                    gem_cmd += ["-n", "/usr/local/bin"]
                gem_cmd.append(gem_name)
                actions.append(
                    self._action(
                        f"gem:{tool}",
                        [self._with_privilege(gem_cmd)],
                        [tool],
                    )
                )
                continue

            system_tool_to_pkg[tool] = self._system_package_name(tool)

        if system_tool_to_pkg:
            if not self.package_manager:
                self.print_warning_message(
                    "System package manager not found. Cannot auto-install: "
                    + ", ".join(sorted(system_tool_to_pkg.keys()))
                )
            else:
                pkg_to_tools: defaultdict[str, list[str]] = defaultdict(list)
                for tool, pkg in system_tool_to_pkg.items():
                    pkg_to_tools[pkg].append(tool)

                package_names = sorted(pkg_to_tools.keys())
                commands = self._build_system_install_commands(package_names)
                verify_names = sorted({tool for tools in pkg_to_tools.values() for tool in tools})
                actions.append(
                    self._action(
                        f"system:{self.package_manager}",
                        commands,
                        verify_names,
                    )
                )

        return actions

    def install_packages(self, packages: List[Dict[str, object]]) -> bool:
        """Execute a normalized installation plan."""
        if not self.is_supported_os or not packages:
            return True

        all_success = True
        installed_tools = set()

        for action in packages:
            action_name = str(action.get("name", "unknown"))
            commands = action.get("commands", []) or []
            verify_names = list(action.get("verify_names", []))

            if not commands:
                continue

            self.print_info_message(f"Installing: {action_name}")

            action_ok = True
            for command in commands:
                if not isinstance(command, list) or not command:
                    action_ok = False
                    break

                try:
                    result = self.execute_command(command)
                except Exception as error:
                    self.print_error_message(
                        message=f"Failed to execute install command for {action_name}",
                        exception_error=error,
                    )
                    action_ok = False
                    break

                if result.returncode != 0:
                    details = (result.stderr or "").strip() or (result.stdout or "").strip()
                    self.print_error_message(
                        message=f"Installation failed for {action_name}",
                        exception_error=details or f"exit code {result.returncode}",
                    )
                    action_ok = False
                    break

            # Clear lookup/probe cache after attempted install.
            self._which_cache.clear()
            self._probe_cache.clear()

            if action_ok and all(self._verify_installation(name) for name in verify_names):
                installed_tools.update(verify_names)
                self.print_success_message(f"Successfully installed {action_name}")
            else:
                all_success = False

        if installed_tools:
            self.print_success_message(
                f"Successfully installed {len(installed_tools)} dependency item(s)."
            )

        return all_success

    def _verify_installation(self, package_name: str) -> bool:
        if package_name == "anthropic":
            return not self._is_pip_package_missing("anthropic")
        return not self._binary_missing(package_name)
