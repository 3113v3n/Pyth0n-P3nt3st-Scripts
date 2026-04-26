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

    # Project-local tool root. Tools installed here avoid macOS SIP-protected
    # paths (`/usr/bin`, system Ruby gem dirs) and never require sudo.
    _TOOLS_DIR_NAME = "tools"
    _TOOLS_SUBDIRS = ("bin", "go", "gems", "pipx")
    _MACPORTS_BIN_DIRS = ("/opt/local/bin", "/opt/local/sbin")
    # Tools only available via Homebrew on macOS (not in MacPorts).
    # Note: findomain is intentionally absent — we download its prebuilt binary.
    _HOMEBREW_ONLY_MACOS_TOOLS: set[str] = set()

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
        "httpx-toolkit": {"args": ["-version"], "contains": ("projectdiscovery",)},
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
        "parsero": "parsero",
        "s3scanner": "s3scanner",
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
        "assetfinder": "github.com/tomnomnom/assetfinder",
        "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx",
        "ffuf": "github.com/ffuf/ffuf/v2",
        "getallurls": "github.com/lc/gau/v2/cmd/gau",
        "httpx-toolkit": "github.com/projectdiscovery/httpx/cmd/httpx",
        "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder",
        "brutespray": "github.com/x90skysn3k/brutespray/v2",
    }

    # Tools installed via RubyGems.
    _GEM_PACKAGES = {
        "aquatone-discover": "aquatone",
        "aquatone-scan": "aquatone",
    }

    # Prebuilt binary downloads — preferred over system package managers for tools
    # that are expensive to compile (e.g. findomain requires LLVM + Rust via brew).
    #
    # Structure per tool:
    #   "repo"           — GitHub owner/repo (only thing that needs updating if
    #                      the project moves; no full URLs hardcoded here)
    #   "asset_patterns" — per "<os_family>-<arch>" substring matched against
    #                      asset names in the latest GitHub release. Substring
    #                      matching means version numbers or minor renames in the
    #                      filename don't break the lookup.
    #
    # Resolution order: GitHub API → constructed fallback URL → skip.
    _DIRECT_DOWNLOADS: dict[str, dict] = {
        "findomain": {
            "repo": "Findomain/Findomain",
            "asset_patterns": {
                "macos-x86_64": "osx-x86_64",
                "macos-arm64":  "osx-arm64",
                "debian-x86_64": "linux.zip",
                "debian-arm64":  "aarch64",
            },
        },
    }

    # OS-specific package aliases for system package managers.
    _SYSTEM_PACKAGE_ALIASES = {
        "debian": {
            "go": "golang-go",
            "java": "default-jdk",
            "d2j-dex2jar": "dex2jar",
            "exiftool": "libimage-exiftool-perl",
            "snap": "snapd",
            "apksigner": "apksigner",
            "zipalign": "zipalign",
        },
        "macos": {
            "adb": "android-platform-tools",
            "apktool": "apktool",
            "amass": "amass",
            "autoconf": "autoconf",
            "automake": "automake",
            "sqlitebrowser": "db-browser-for-sqlite",
            "exiftool": "exiftool",
            # findomain omitted — installed via prebuilt binary download, not brew
            "java": "openjdk",
            "d2j-dex2jar": "dex2jar",
            "pkg-config": "pkg-config",
            "radare2": "radare2",
            "sqlite3": "sqlite",
            "usbmuxd": "libusbmuxd",
        },
        "macports": {
            "adb": "android-platform-tools",
            "apktool": "apktool",
            "amass": "amass",
            "autoconf": "autoconf",
            "automake": "automake",
            "d2j-dex2jar": "dex2jar",
            "exiftool": "p5-image-exiftool",
            "findomain": "findomain",
            "java": "openjdk21",
            "nmap": "nmap",
            "pkg-config": "pkgconfig",
            "radare2": "radare2",
            "sqlite3": "sqlite3",
            "sqlitebrowser": "sqlitebrowser",
            "usbmuxd": "libusbmuxd",
            "xmlstarlet": "xmlstarlet",
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

    _OS_LIMITED_TOOLS = {
        "apksigner": {"debian"},
        "snap": {"debian"},
        "checkinstall": {"debian"},
        "zipalign": {"debian"},
    }

    def __init__(self) -> None:
        super().__init__()
        self.operating_system = platform.system().lower()
        self.os_family = self._detect_os_family()
        self.package_manager = self._detect_system_package_manager()
        self.is_supported_os = None
        self.tools_root = self._resolve_tools_root()
        self._prepend_tools_bin_to_path()
        self._which_cache: dict[str, str | None] = {}
        self._probe_cache: dict[tuple[str, tuple[str, ...]], bool] = {}
        self._search_path = self._build_search_path()

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.operating_system = platform.system().lower()
        self.os_family = self._detect_os_family()
        self.package_manager = self._detect_system_package_manager()
        self.is_supported_os = None
        self.tools_root = self._resolve_tools_root()
        self._prepend_tools_bin_to_path()
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
            macos_path = os.pathsep.join([*self._MACPORTS_BIN_DIRS, os.environ.get("PATH", "")])
            if shutil.which("port", path=macos_path):
                self._prepend_paths_to_env(list(self._MACPORTS_BIN_DIRS))
                return "port"
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
                "No system package manager detected (apt/port/brew/winget/choco). "
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
            str(Path(sys.executable).resolve().parent),
            str(self._tools_bin_dir()),
            *self._MACPORTS_BIN_DIRS,
            *self._homebrew_ruby_bin_dirs(),
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

    # ------------------------------------------------------------------
    # Project-local tool directory (avoids sudo / SIP issues on macOS)
    # ------------------------------------------------------------------

    def _resolve_tools_root(self) -> Path:
        """Return <repo>/tools/. Created lazily before installs run."""
        return Path(__file__).resolve().parents[1] / self._TOOLS_DIR_NAME

    def _tools_bin_dir(self) -> Path:
        return self.tools_root / "bin"

    def _homebrew_ruby_bin_dirs(self) -> list[str]:
        """Likely Homebrew Ruby bin dirs.

        macOS ships an old system Ruby whose SDK headers can be incomplete for
        native extensions. Homebrew's Ruby is preferred for gem-based tools.
        """
        if self.os_family != "macos":
            return []

        dirs: list[str] = []
        try:
            brew = shutil.which("brew")
            if brew:
                result = self.execute_command([brew, "--prefix", "ruby"], timeout=5)
                if result.returncode == 0:
                    prefix = result.stdout.strip()
                    if prefix:
                        dirs.append(str(Path(prefix) / "bin"))
        except Exception:
            pass

        dirs.extend([
            "/opt/homebrew/opt/ruby/bin",
            "/usr/local/opt/ruby/bin",
        ])
        return dirs

    @staticmethod
    def _is_macos_system_ruby_path(path: str | None) -> bool:
        if not path:
            return False
        resolved = str(Path(path).resolve())
        return resolved.startswith("/usr/bin/") or resolved.startswith("/System/Library/Frameworks/Ruby.framework/")

    def _preferred_gem_executable(self) -> str | None:
        """Return a usable gem executable, preferring Homebrew Ruby on macOS."""
        candidates: list[str] = []

        configured = os.environ.get("PENTEST_GEM")
        if configured:
            candidates.append(configured)

        if self.os_family == "macos":
            for bin_dir in self._homebrew_ruby_bin_dirs():
                candidates.append(str(Path(bin_dir) / "gem"))

        resolved = shutil.which("gem", path=self._search_path)
        if resolved:
            candidates.append(resolved)

        seen: set[str] = set()
        for candidate in candidates:
            if not candidate or candidate in seen:
                continue
            seen.add(candidate)
            if self.os_family == "macos" and self._is_macos_system_ruby_path(candidate):
                continue
            try:
                result = self.execute_command([candidate, "--version"], timeout=5)
            except Exception:
                continue
            if result.returncode == 0:
                return candidate

        if self.os_family != "macos":
            return resolved
        return None

    def _pipx_command(self) -> list[str]:
        """Return a pipx invocation that works before and after bootstrap."""
        resolved = shutil.which("pipx", path=self._search_path)
        if resolved:
            return [resolved]
        return [sys.executable, "-m", "pipx"]

    def _pipx_available(self) -> bool:
        try:
            result = self.execute_command([*self._pipx_command(), "--version"], timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def _prepend_tools_bin_to_path(self) -> None:
        """Ensure subprocesses spawned by the framework see project-local tools.

        The framework looks tools up by bare name (e.g. ``["nuclei", ...]``),
        which goes through ``subprocess.run`` and inherits the parent's PATH.
        Prepending ``tools/bin`` here makes every subsequent invocation — and
        every ``shutil.which`` check — pick up tools we installed locally.
        """
        bin_paths = [
            str(Path(sys.executable).resolve().parent),
            str(self._tools_bin_dir()),
            *self._MACPORTS_BIN_DIRS,
            *self._homebrew_ruby_bin_dirs(),
        ]
        self._prepend_paths_to_env(bin_paths)

        gems_dir = str(self.tools_root / "gems")
        os.environ.setdefault("GEM_HOME", gems_dir)
        gem_path_entries = os.environ.get("GEM_PATH", "").split(os.pathsep)
        if gems_dir not in gem_path_entries:
            os.environ["GEM_PATH"] = os.pathsep.join([gems_dir, *[entry for entry in gem_path_entries if entry]])

    @staticmethod
    def _prepend_paths_to_env(paths: list[str]) -> None:
        current = os.environ.get("PATH", "")
        path_entries = current.split(os.pathsep) if current else []
        for bin_path in reversed(paths):
            if bin_path and bin_path not in path_entries:
                path_entries.insert(0, bin_path)
        os.environ["PATH"] = os.pathsep.join(path_entries)

    def _ensure_tools_dirs(self) -> None:
        """Create the per-toolchain subdirectories. Called before installs."""
        for sub in self._TOOLS_SUBDIRS:
            (self.tools_root / sub).mkdir(parents=True, exist_ok=True)

    def _tool_install_env(self) -> dict[str, str]:
        """Env vars that redirect go/gem/pipx installs into ``<repo>/tools/``."""
        env = os.environ.copy()
        bin_dir = str(self._tools_bin_dir())
        gems_dir = str(self.tools_root / "gems")
        env["GOBIN"] = bin_dir
        env["GOPATH"] = str(self.tools_root / "go")
        env["GEM_HOME"] = gems_dir
        env["GEM_PATH"] = gems_dir
        env["PIPX_HOME"] = str(self.tools_root / "pipx")
        env["PIPX_BIN_DIR"] = bin_dir
        # Make sure bindir is on PATH for any post-install hook (e.g. pipx ensurepath).
        env["PATH"] = os.pathsep.join([
            bin_dir,
            *self._homebrew_ruby_bin_dirs(),
            env.get("PATH", ""),
        ])
        return env

    def _direct_download_url(self, tool_name: str) -> str | None:
        """Resolve a prebuilt-binary download URL for ``tool_name``.

        Looks up the tool in ``_DIRECT_DOWNLOADS``, determines the right
        asset pattern for the current OS/arch, then asks the GitHub API for
        the real URL of the matching asset in the latest release.

        Falls back to a constructed ``releases/latest/download/<pattern>`` URL
        when the API is unreachable (e.g. rate-limited, no network).

        Returns ``None`` when no entry exists for this tool/OS combination,
        allowing the caller to fall through to the system package manager.
        """
        entry = self._DIRECT_DOWNLOADS.get(tool_name)
        if not entry:
            return None

        repo = entry.get("repo", "")
        patterns: dict = entry.get("asset_patterns", {})
        machine = platform.machine().lower()
        arch = "arm64" if machine in ("arm64", "aarch64") else "x86_64"
        key = f"{self.os_family}-{arch}"
        pattern = patterns.get(key) or patterns.get(f"{self.os_family}-x86_64")

        if not pattern or not repo:
            return None

        # Prefer a live GitHub API lookup — resilient to filename changes.
        resolved = self._github_latest_asset_url(repo, pattern)
        if resolved:
            return resolved

        # Fallback: constructed URL using the stored pattern as a filename.
        # Works as long as the project uses the standard GitHub releases path.
        self.print_warning_message(
            f"GitHub API lookup failed for {tool_name}; "
            "falling back to constructed release URL."
        )
        return f"https://github.com/{repo}/releases/latest/download/{pattern}"

    @staticmethod
    def _github_latest_asset_url(repo: str, asset_pattern: str) -> str | None:
        """Return the browser download URL of the latest release asset whose
        name contains ``asset_pattern`` (case-insensitive substring match).

        Substring matching tolerates version numbers, minor renames, or
        extension changes in the asset filename without needing a code update.
        Returns ``None`` on any network or parsing failure.
        """
        import json
        import urllib.request

        try:
            api_url = f"https://api.github.com/repos/{repo}/releases/latest"
            req = urllib.request.Request(
                api_url,
                headers={"Accept": "application/vnd.github+json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            for asset in data.get("assets", []):
                if asset_pattern.lower() in asset["name"].lower():
                    return asset["browser_download_url"]
        except Exception:
            pass
        return None

    def _build_download_action(self, tool_name: str, url: str) -> Dict[str, object]:
        """Return an action that fetches a prebuilt binary into ``tools/bin/``.

        Handles both bare binaries and ``.zip`` archives. Uses ``curl`` for the
        download when available; always uses Python's ``zipfile`` for extraction
        so there is no dependency on a system ``unzip``.
        """
        dest = str(self._tools_bin_dir() / tool_name)
        is_zip = url.lower().endswith(".zip")

        if is_zip:
            # Single Python call: download zip into a temp file, extract the
            # binary (matched by name), place it in tools/bin/, then clean up.
            extract_script = (
                "import urllib.request, zipfile, tempfile, os, shutil; "
                f"tmp = tempfile.mktemp(suffix='.zip'); "
                f"urllib.request.urlretrieve({url!r}, tmp); "
                f"z = zipfile.ZipFile(tmp); "
                f"members = [m for m in z.namelist() if os.path.basename(m).split('.')[0] == {tool_name!r}]; "
                f"src = members[0] if members else z.namelist()[0]; "
                f"data = z.open(src).read(); "
                f"open({dest!r}, 'wb').write(data); "
                f"os.chmod({dest!r}, 0o755); "
                f"os.unlink(tmp)"
            )
            commands: list[list[str]] = [[sys.executable, "-c", extract_script]]
        elif shutil.which("curl"):
            commands = [
                ["curl", "-fsSL", "--output", dest, url],
                ["chmod", "+x", dest],
            ]
        else:
            # Pure-Python fallback for bare binaries when curl is absent.
            commands = [
                [
                    sys.executable, "-c",
                    f"import urllib.request, os; urllib.request.urlretrieve({url!r}, {dest!r}); os.chmod({dest!r}, 0o755)",
                ]
            ]
        return self._action(f"download:{tool_name}", commands, [tool_name])

    def _system_install_env(self, package_manager: str | None = None) -> dict[str, str]:
        """Env vars for non-language system package managers."""
        manager = package_manager or self.package_manager
        env = os.environ.copy()
        if manager == "port":
            entries = env.get("PATH", "").split(os.pathsep) if env.get("PATH") else []
            for bin_path in reversed(self._MACPORTS_BIN_DIRS):
                if bin_path not in entries:
                    entries.insert(0, bin_path)
            env["PATH"] = os.pathsep.join(entries)
        if manager == "brew":
            # Avoid long, implicit update steps and make brew output deterministic
            # inside non-interactive framework runs.
            env.setdefault("HOMEBREW_NO_AUTO_UPDATE", "1")
            env.setdefault("HOMEBREW_NO_INSTALL_CLEANUP", "1")
            env.setdefault("HOMEBREW_NO_ENV_HINTS", "1")
        return env

    def _patch_project_gem_binstubs(self, executable_names: list[str]) -> None:
        """Make generated RubyGems binstubs find repo-local gems at runtime."""
        gems_dir = str(self.tools_root / "gems")
        marker = "# Pyth0n-P3nt3st-Scripts local gem path"

        for executable in executable_names:
            script_path = self._tools_bin_dir() / executable
            if not script_path.exists():
                continue

            try:
                text = script_path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue

            if "Gem.activate_bin_path" not in text:
                continue

            changed = False
            if marker not in text:
                lines = text.splitlines()
                insert_at = 1 if lines and lines[0].startswith("#!") else 0
                snippet = [
                    marker,
                    f"ENV['GEM_HOME'] ||= {gems_dir!r}",
                    "ENV['GEM_PATH'] = [ENV['GEM_HOME'], ENV['GEM_PATH']].compact.join(File::PATH_SEPARATOR)",
                ]
                lines[insert_at:insert_at] = snippet
                text = "\n".join(lines) + "\n"
                changed = True

            if "Gem.use_paths(" not in text:
                gem_paths = (
                    "require 'rubygems'\n"
                    "Gem.use_paths(ENV['GEM_HOME'], ENV['GEM_PATH'].split(File::PATH_SEPARATOR))\n"
                )
                text = text.replace("require 'rubygems'\n", gem_paths, 1)
                changed = True

            if changed:
                script_path.write_text(text, encoding="utf-8")

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
        if package_name == "pipx":
            return not self._pipx_available()

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
                continue
            return False

        return True

    def _is_tool_supported_on_current_os(self, tool_name: str) -> bool:
        supported_os = self._OS_LIMITED_TOOLS.get(tool_name)
        return not supported_os or self.os_family in supported_os

    def _is_package_missing(self, package_name: str) -> bool:
        if not self.is_supported_os:
            return False

        if not self._is_tool_supported_on_current_os(package_name):
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

        skipped_tools = [
            tool for tool in required_tools
            if not self._is_tool_supported_on_current_os(tool)
        ]
        if skipped_tools:
            self.print_warning_message(
                "Skipping OS-specific dependency item(s) on this platform: "
                + ", ".join(sorted(skipped_tools))
            )

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

    def _system_package_alias_key(self, package_manager: str | None = None) -> str:
        manager = package_manager or self.package_manager
        if self.os_family != "windows":
            if self.os_family == "macos" and manager == "port":
                return "macports"
            return self.os_family
        return "windows-winget" if manager == "winget" else "windows-choco"

    def _system_package_name(self, tool_name: str, package_manager: str | None = None) -> str:
        alias_key = self._system_package_alias_key(package_manager)
        mapping = self._SYSTEM_PACKAGE_ALIASES.get(alias_key, {})
        return mapping.get(tool_name, tool_name)

    def _build_system_install_commands(
        self,
        package_names: list[str],
        package_manager: str | None = None,
    ) -> list[list[str]]:
        manager = package_manager or self.package_manager
        if not package_names or not manager:
            return []

        if manager == "apt":
            return [self._with_privilege(["apt-get", "install", "-y", *package_names])]

        if manager == "brew":
            return [["brew", "install", package_name] for package_name in package_names]

        if manager == "port":
            return [self._with_privilege(["port", "install", package_name]) for package_name in package_names]

        if manager == "choco":
            return [["choco", "install", "-y", *package_names]]

        if manager == "winget":
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

    def _system_manager_for_tool(self, tool_name: str) -> str | None:
        """Return the system package manager that should install a tool."""
        if (
            self.os_family == "macos"
            and self.package_manager == "port"
            and tool_name in self._HOMEBREW_ONLY_MACOS_TOOLS
        ):
            if shutil.which("brew", path=self._search_path):
                return "brew"
            self.print_warning_message(
                f"Skipping auto-install for '{tool_name}': it is not available in MacPorts "
                "and Homebrew was not detected."
            )
            return None
        return self.package_manager

    def _action(
        self,
        name: str,
        commands: list[list[str]],
        verify_names: list[str],
        env: dict[str, str] | None = None,
    ) -> Dict[str, object]:
        return {
            "name": name,
            "commands": commands,
            "verify_names": verify_names,
            "env": env,
        }

    def _build_install_plan(self, missing_tools: list[str]) -> list[Dict[str, object]]:
        """Build normalized installation actions from missing tool identifiers."""
        actions: list[Dict[str, object]] = []
        system_tool_to_install: dict[str, tuple[str, str]] = {}
        skipped_system_tools: list[str] = []

        needs_pipx = any(tool in self._PIPX_PACKAGES for tool in missing_tools)
        needs_go = any(tool in self._GO_MODULES for tool in missing_tools)
        needs_gem = any(tool in self._GEM_PACKAGES for tool in missing_tools)
        needs_download = any(self._direct_download_url(t) for t in missing_tools)

        # Materialize <repo>/tools/* once if any install will land there.
        if needs_pipx or needs_go or needs_gem or needs_download:
            self._ensure_tools_dirs()

        if needs_pipx and not self._pipx_available():
            actions.append(
                self._action(
                    "pipx",
                    [
                        [sys.executable, "-m", "pip", "install", "pipx"],
                    ],
                    ["pipx"],
                    env=self._tool_install_env(),
                )
            )

        if needs_go and self._binary_missing("go"):
            go_manager = self._system_manager_for_tool("go")
            go_cmds = self._build_system_install_commands(
                [self._system_package_name("go", go_manager)],
                go_manager,
            )
            if go_cmds:
                actions.append(self._action("go", go_cmds, ["go"]))
            else:
                self.print_warning_message("'go' is missing and no package manager is available to install it.")

        if needs_gem and not self._preferred_gem_executable():
            ruby_manager = self._system_manager_for_tool("ruby")
            ruby_cmds = self._build_system_install_commands(
                [self._system_package_name("ruby", ruby_manager)],
                ruby_manager,
            )
            if ruby_cmds:
                actions.append(self._action("ruby", ruby_cmds, ["ruby", "gem"]))
            else:
                self.print_warning_message("'ruby/gem' is missing and no package manager is available to install it.")

        # Fine-grained installers (python/pipx/go/gem), then system package fallback.
        planned_gems: set[str] = set()
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
                # directly rather than `python -m pipx`. PIPX_HOME / PIPX_BIN_DIR
                # in the env redirect the install into <repo>/tools/, so no
                # global state is touched and no sudo is required.
                actions.append(
                    self._action(
                        f"pipx:{tool}",
                        [[*self._pipx_command(), "install", package_ref]],
                        [tool],
                        env=self._tool_install_env(),
                    )
                )
                continue

            if tool in self._GO_MODULES:
                module = self._GO_MODULES[tool]
                # GOBIN in the env makes `go install` drop the binary into
                # <repo>/tools/bin/ instead of ~/go/bin.
                actions.append(
                    self._action(
                        f"go:{tool}",
                        [["go", "install", f"{module}@latest"]],
                        [tool],
                        env=self._tool_install_env(),
                    )
                )
                continue

            if tool in self._GEM_PACKAGES:
                gem_name = self._GEM_PACKAGES[tool]
                if gem_name in planned_gems:
                    continue
                planned_gems.add(gem_name)
                verify_tools = sorted(
                    item for item in missing_tools
                    if self._GEM_PACKAGES.get(item) == gem_name
                )
                # --install-dir + --bindir keep both the gem files and the
                # binstubs inside <repo>/tools/, sidestepping macOS SIP and
                # avoiding a sudo prompt entirely.
                gems_dir = str(self.tools_root / "gems")
                bin_dir = str(self._tools_bin_dir())
                gem_executable = self._preferred_gem_executable() or "gem"
                actions.append(
                    self._action(
                        f"gem:{gem_name}",
                        [[gem_executable, "install",
                          "--install-dir", gems_dir,
                          "--bindir", bin_dir,
                          gem_name]],
                        verify_tools,
                        env=self._tool_install_env(),
                    )
                )
                continue

            # Prefer a prebuilt binary download over the system package manager
            # for tools where compilation would be required (e.g. findomain pulls
            # in LLVM + Rust when installed via brew — a multi-hour build).
            download_url = self._direct_download_url(tool)
            if download_url:
                actions.append(self._build_download_action(tool, download_url))
                continue

            manager = self._system_manager_for_tool(tool)
            if manager:
                system_tool_to_install[tool] = (manager, self._system_package_name(tool, manager))
            else:
                skipped_system_tools.append(tool)

        if skipped_system_tools and not self.package_manager:
            self.print_warning_message(
                "System package manager not found. Cannot auto-install: "
                + ", ".join(sorted(skipped_system_tools))
            )

        if system_tool_to_install:
            manager_pkg_to_tools: defaultdict[tuple[str, str], list[str]] = defaultdict(list)
            for tool, (manager, pkg) in system_tool_to_install.items():
                manager_pkg_to_tools[(manager, pkg)].append(tool)

            tools_by_manager: defaultdict[str, dict[str, list[str]]] = defaultdict(dict)
            for (manager, pkg), tools in manager_pkg_to_tools.items():
                tools_by_manager[manager][pkg] = tools

            for manager, pkg_to_tools in sorted(tools_by_manager.items()):
                package_names = sorted(pkg_to_tools.keys())
                commands = self._build_system_install_commands(package_names, manager)
                verify_names = sorted({tool for tools in pkg_to_tools.values() for tool in tools})
                actions.append(
                    self._action(
                        f"system:{manager}",
                        commands,
                        verify_names,
                        env=self._system_install_env(manager),
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
                    action_env = action.get("env")
                    result = (
                        self.execute_command(command, env=action_env, timeout=900)
                        if action_env
                        else self.execute_command(command, timeout=900)
                    )
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

            if action_ok and action_name.startswith("gem:"):
                self._patch_project_gem_binstubs(verify_names)

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
