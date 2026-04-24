"""
mobile_commands.py — Static analysis engine for Android APK and iOS IPA files.

This module now performs a Python-native, parallelized scan with optional
integration points for external tools (apktool, nuclei) when available.

Key improvements:
- Safer command execution (list-form subprocess calls only for external tools)
- Faster scanning (single-pass per file, thread pool processing)
- Lower-noise outputs (filtered base64 decoding, categorized findings)
- Source-level detections for integrity / anti-tamper mechanisms and risks
- Structured output (text reports + JSON summary)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import base64
import hashlib
import ipaddress
import json
import math
import os
import plistlib
import re
import shutil
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile

from handlers import FileHandler, ScreenHandler
from utils.shared import Commands, Config, CustomDecorators


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    severity: str
    file: str
    evidence: str


class MobileCommands(
    FileHandler,
    Config,
    Commands,
    ScreenHandler,
    CustomDecorators,
):
    """Mobile static analysis commands for APK/IPA packages."""

    # File handling/performance tunables
    MAX_FILE_SIZE_BYTES = 8 * 1024 * 1024
    MAX_TEXT_CHARS_PER_FILE = 500_000
    MAX_STRINGS_PER_FILE = 5_000
    THREAD_FACTOR = 2
    NUCLEI_TEMPLATE_SYNC_TTL_SECONDS = 24 * 60 * 60

    # Binary/text extraction
    PRINTABLE_RE = re.compile(rb"[\x20-\x7E]{8,}")
    URL_RE = re.compile(r"\b(?:https?|wss?)://[^\s\"'<>]+", re.IGNORECASE)
    IP_RE = re.compile(
        r"(?<!\d\.)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\.\d)"
    )
    URL_TRAILING_JUNK_RE = re.compile(r"[.,;:)\]}>\"']+$")
    URL_PLACEHOLDER_RE = re.compile(r"%[a-zA-Z]")
    HOSTNAME_RE = re.compile(
        r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
        re.IGNORECASE,
    )
    IPV4_EXACT_RE = re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$"
    )
    IP_CONTEXT_RE = re.compile(
        r"(?i)\b(?:ip|host|addr|address|src|source|dst|dest|destination|from|to|endpoint|server|dns)\b"
    )
    BASE64_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9+/]{24,}={0,2})\b")
    BASE64_MAX_DECODE_DEPTH = 5
    MAX_BASE64_DECODE_BYTES = 8 * 1024 * 1024

    # Useful extensions for direct text decode
    TEXT_EXTENSIONS = {
        ".xml", ".json", ".txt", ".cfg", ".conf", ".ini", ".properties", ".yaml", ".yml",
        ".js", ".html", ".htm", ".css", ".csv", ".md", ".smali", ".java", ".kt", ".kts",
        ".swift", ".m", ".mm", ".plist", ".entitlements", ".gradle", ".pro", ".pbxproj",
    }
    BINARY_SKIP_EXTENSIONS = {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".ico", ".mp3", ".wav", ".ogg",
        ".mp4", ".mov", ".avi", ".ttf", ".otf", ".woff", ".woff2", ".so",
    }

    # URLs that are typically noise for security triage
    URL_IGNORE_RE = re.compile(r"\.(?:css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)(?:\?|$)", re.IGNORECASE)
    URL_NOISE_HOSTS = {
        "schemas.android.com",
        "android.googlesource.com",
        "www.w3.org",
    }
    REPO_REFERENCE_HOSTS = {"github.com", "www.github.com", "gitlab.com", "bitbucket.org"}
    NETWORK_CONTEXT_HINTS = (
        "http://", "https://", "wss://", "host", "ip", "endpoint",
        "server", "socket", "connect", "address", "dns",
    )
    VERSION_CONTEXT_HINTS = (
        "version", "openssl", "libssl", "changelog", "release", "build", "sdk",
    )
    OID_CONTEXT_HINTS = (
        "oid", "asn1", "x509", "pkcs", "objectidentifier", "object identifier",
    )
    KNOWN_PUBLIC_SERVICE_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"}

    # Hardcoded secret detectors
    SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
        ("AWS Access Key", "high", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
        ("Google API Key", "high", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("Stripe Live Key", "high", re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
        ("GitHub Token", "high", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
        ("JWT Token", "medium", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
        (
            "Hardcoded Credential Assignment",
            "high",
            re.compile(
                r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b"
                r"\s*(?:[:=]|=>)\s*[\"'][^\"'\n]{6,}[\"']"
            ),
        ),
        (
            "Bearer/Auth Header Token",
            "high",
            re.compile(r"(?i)\b(?:authorization|bearer)\b[^\n]{0,120}"),
        ),
    ]

    # Generic noisy placeholders that should not be reported as secrets.
    NOISE_SECRET_VALUES = {
        "password", "passwd", "secret", "token", "apikey", "api_key", "changeme",
        "default", "dummy", "sample", "example", "test", "none", "null", "undefined",
        "your_password", "your_token", "insert_here",
    }
    SECRET_VALUE_RE = re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|client[_-]?secret|access[_-]?key)\b"
        r"\s*(?:[:=]|=>)\s*[\"']([^\"'\n]{6,})[\"']"
    )

    # Potential insecure implementations
    RISK_INDICATORS: list[tuple[str, str, str, tuple[str, ...]]] = [
        (
            "webview",
            "Potentially Unsafe WebView Usage",
            "medium",
            (
                "setjavascriptenabled(true)",
                "addjavascriptinterface(",
                "setallowfileaccess(true)",
                "setallowuniversalaccessfromfileurls(true)",
                "onreceivedsslerror",
                ".proceed()",
            ),
        ),
        (
            "tls",
            "Potential TLS Trust Bypass",
            "high",
            (
                "allowallhostnameverifier",
                "trustallcerts",
                "x509trustmanager",
                "hostnameverifier",
            ),
        ),
    ]

    # Additional easy-to-miss vulnerability heuristics (regex based).
    ADVANCED_RISK_REGEX: list[tuple[str, str, str, re.Pattern[str]]] = [
        (
            "crypto",
            "Weak Hash Algorithm Usage",
            "high",
            re.compile(r"(?i)messagedigest\.getinstance\(\"(?:md5|sha-1)\"\)"),
        ),
        (
            "crypto",
            "Weak Cipher Mode (ECB) Usage",
            "high",
            re.compile(r"(?i)cipher\.getinstance\(\"[^\"]*ecb[^\"]*\"\)"),
        ),
        (
            "crypto",
            "Weak Cipher Algorithm Usage",
            "high",
            re.compile(r"(?i)cipher\.getinstance\(\"(?:des|desede|rc2|rc4)[^\"]*\"\)"),
        ),
        (
            "crypto",
            "Potential Insecure PRNG (SHA1PRNG)",
            "medium",
            re.compile(r"(?i)sha1prng"),
        ),
        (
            "logging",
            "Sensitive Data Logged to Console",
            "medium",
            re.compile(r"(?i)log\.[vdiew]\([^\n]*(?:password|token|secret|api[_-]?key)"),
        ),
        (
            "data_access",
            "Potential SQL Injection Sink (rawQuery Concatenation)",
            "high",
            re.compile(r"(?i)rawquery\s*\([^\n]*\+[^\n]*\)"),
        ),
        (
            "intent_security",
            "Potential Broadcast Exposure (Heuristic)",
            "low",
            re.compile(r"(?i)\bsendbroadcast\s*\("),
        ),
    ]

    # Severity model used for report scoring.
    SEVERITY_WEIGHTS = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1,
    }

    # Security controls / integrity signals present in code
    CONTROL_INDICATORS: list[tuple[str, str, str, tuple[str, ...]]] = [
        (
            "integrity",
            "Play Integrity/SafetyNet Signal",
            "info",
            ("integritymanager", "play integrity", "safetynet", "ctsprofilematch", "basicintegrity"),
        ),
        (
            "anti_tamper",
            "App Signature Validation Logic",
            "info",
            (
                "getsigningcertificates",
                "packageinfo.signatures",
                "signinginfo",
                "getpackageinfo(",
                "certificatefactory.getinstance",
                "messagedigest.getinstance(\"sha-256\")",
            ),
        ),
        (
            "anti_root",
            "Root/Jailbreak Detection Logic",
            "info",
            (
                "isdevice rooted",
                "jailbreak",
                "cydia",
                "magisk",
                "su/bin/su",
                "test-keys",
                "ro.debuggable",
                "ro.secure",
            ),
        ),
        (
            "anti_debug",
            "Anti-Debugging Signal",
            "info",
            ("isdebuggerconnected", "debugger", "ptrace", "tracerpid"),
        ),
        (
            "pinning",
            "Certificate Pinning Signal",
            "info",
            ("certificatepinner", "network_security_config", "sec_trust_evaluate", "trustkit"),
        ),
        (
            "secure_storage",
            "Secure Storage API Usage",
            "info",
            ("androidkeystore", "encryptedsharedpreferences", "keychain", "ksecattr"),
        ),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.mobile_output_dir = ""
        self.file_type = ""
        self.folder_name = ""
        self.file_name = ""
        self.file_count = 0
        self.templates_folder = ""
        self.debug = False
        self.grep_cmd = "grep"  # retained for backward compatibility

        self._scan_stats: dict = {}
        self._nuclei_templates_synced = False

    # ------------------------------------------------------------------
    # Legacy compatibility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_file_path(path: str) -> str:
        if "\x00" in path:
            raise ValueError(f"Null byte detected in path: {path!r}")
        if ".." in Path(path).parts:
            raise ValueError(f"Path traversal detected in path: {path!r}")
        return path

    @staticmethod
    def rename_folders_with_spaces(path: str) -> None:
        for root, dirs, _ in os.walk(path):
            for dir_name in dirs:
                if " " in dir_name:
                    old_path = os.path.join(root, dir_name)
                    new_path = os.path.join(root, dir_name.replace(" ", "_"))
                    os.rename(old_path, new_path)

    def update_grep_cmd(self) -> None:
        self.grep_cmd = "ggrep"

    @staticmethod
    def format_content(content: str) -> str:
        content = re.sub(r"\\n", "\n", content)
        content = re.sub(r"\\t", "\t", content)
        content = re.sub(r"\\r", "\r", content)
        return content

    def push_certs(self, certificate: str) -> None:
        safe_cert = self._validate_file_path(certificate)
        self.execute_command(["adb", "push", safe_cert, "/storage/emulated/0/"])

    def pull_package_with_keyword(self, keyword: str) -> None:
        """Best-effort ADB APK pull without shell pipelines."""
        if not shutil.which("adb"):
            self.print_error_message("adb not found on PATH")
            return

        # 1) list packages
        packages_out = self.get_process_output(["adb", "shell", "pm", "list", "packages"])
        pkg = ""
        for line in packages_out.splitlines():
            line = line.strip()
            if keyword.lower() in line.lower() and line.startswith("package:"):
                pkg = line.split(":", 1)[1].strip()
                break

        if not pkg:
            self.print_error_message("Package not found")
            return

        # 2) resolve apk path
        paths_out = self.get_process_output(["adb", "shell", "pm", "path", pkg])
        apk_path = ""
        for line in paths_out.splitlines():
            line = line.strip()
            if line.startswith("package:") and "base.apk" in line:
                apk_path = line.split(":", 1)[1].strip()
                break

        if not apk_path:
            self.print_error_message("APK path not found.")
            return

        # 3) pull apk
        result = self.execute_command(["adb", "pull", apk_path, "./"])
        if result.returncode == 0:
            self.print_success_message(f"Successfully pulled {apk_path}")
        else:
            self.print_error_message("Failed to pull APK", exception_error=result.stderr.strip())

    # ------------------------------------------------------------------
    # Scan setup / extraction
    # ------------------------------------------------------------------

    def _get_folder_name(self, platform: str, package: str) -> str:
        self.templates_folder = f"{self.output_directory}/mobile-nuclei-templates"
        platform_name = platform.title() if platform.lower() == "android" else platform
        base_dir = self.output_directory

        filename_without_ext = self.get_filename_without_extension(package)
        self.file_name = self.remove_spaces(filename_without_ext)

        self.create_folder(platform_name, search_path=base_dir)
        self.mobile_output_dir = f"{base_dir}/{platform_name}"
        return self.remove_spaces(f"{self.mobile_output_dir}/{filename_without_ext}")

    def _extract_with_apktool(self, package: str, folder_name: str) -> bool:
        if not shutil.which("apktool"):
            return False
        cmd = ["apktool", "d", "-f", package, "-o", folder_name]
        result = self.execute_command(cmd)
        if result.returncode != 0:
            if self.debug:
                self.print_warning_message("apktool decompile failed", file_path=result.stderr.strip())
            return False
        return True

    @staticmethod
    def _extract_archive(package: str, folder_name: str) -> None:
        with zipfile.ZipFile(package, "r") as archive:
            archive.extractall(folder_name)

    def _unzip_package(self, package: str, folder_name: str) -> str:
        """Extract APK/IPA package and return extraction method used."""
        safe_package = self._validate_file_path(package)
        safe_folder = self._validate_file_path(folder_name)

        if self.check_folder_exists(safe_folder):
            return "cached"

        self.print_info_message(f"Decompiling/extracting {self.file_name} application...")

        # Android: prefer apktool for richer decompiled source (smali/resources)
        if self.file_type.lower() == "apk":
            if self._extract_with_apktool(safe_package, safe_folder):
                self.print_success_message("Decompiling successful with apktool")
                return "apktool"

        # Fallback: archive extraction for APK and default for IPA
        try:
            self._extract_archive(safe_package, safe_folder)
            self.print_success_message("Archive extraction successful")
            return "zip"
        except (zipfile.BadZipFile, OSError) as error:
            self.print_error_message("Failed to extract package", exception_error=error)
            raise

    def decompile_application(self, package: str) -> tuple[str, str]:
        self.file_type = self.get_file_extension(package).lower()
        if self.file_type not in {"apk", "ipa"}:
            raise ValueError(f"Unsupported mobile package type: {self.file_type}")

        platform = "android" if self.file_type == "apk" else "iOS"
        self.folder_name = self._get_folder_name(platform, package)
        method = self._unzip_package(package, self.folder_name)
        return self.folder_name, method

    def create_subfolder(self) -> None:
        new_folder_name = f"{self.file_name}_scan_results"
        updated_output_directory = f"{self.folder_name}_scan_results"
        self.create_folder(folder_name=new_folder_name, search_path=self.mobile_output_dir)
        self.mobile_output_dir = updated_output_directory

    # ------------------------------------------------------------------
    # Core analyzers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_relpath(path: Path, root: Path) -> str:
        try:
            return str(path.relative_to(root))
        except ValueError:
            return str(path)

    @staticmethod
    def _entropy(value: str) -> float:
        """Compute Shannon entropy for quick randomness estimation."""
        if not value:
            return 0.0
        counts = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        total = len(value)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * (0.0 if p == 0 else math.log2(p))
        return entropy

    @classmethod
    def _severity_weight(cls, severity: str) -> int:
        return cls.SEVERITY_WEIGHTS.get(severity.lower(), 1)

    @classmethod
    def _is_valuable_url(cls, url: str) -> bool:
        """Filter framework/library/documentation URLs that are typically noise."""
        cleaned = cls._sanitize_url_candidate(url)
        if not cleaned:
            return False
        try:
            parsed = urlparse(cleaned)
        except ValueError:
            return False
        if parsed.scheme.lower() not in {"http", "https", "wss"}:
            return False
        host = (parsed.hostname or "").lower()
        if not cls._is_valid_url_host(host):
            return False
        if host in cls.URL_NOISE_HOSTS:
            return False
        if cls._is_source_repo_reference_url(host, parsed.path or ""):
            return False
        if cls.URL_PLACEHOLDER_RE.search(cleaned):
            return False
        if cls.URL_IGNORE_RE.search(cleaned):
            return False
        return True

    @classmethod
    def _canonicalize_url(cls, url: str) -> str:
        """Canonical URL for reporting: drop query/fragment and normalize root slash."""
        cleaned = cls._sanitize_url_candidate(url)
        if not cleaned:
            return ""
        parsed = urlparse(cleaned)
        host = (parsed.hostname or "").lower()
        if not cls._is_valid_url_host(host):
            return ""
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        path = parsed.path or ""
        if path == "/":
            path = ""
        elif path:
            path = path.rstrip("/")
        return f"{parsed.scheme.lower()}://{netloc}{path}"

    @classmethod
    def _sanitize_url_candidate(cls, url: str) -> str:
        if not url:
            return ""
        cleaned = cls.URL_TRAILING_JUNK_RE.sub("", str(url).strip())
        if (
            not cleaned
            or "\\" in cleaned
            or cleaned.endswith("://")
            or cleaned.endswith("://.")
            or cleaned.endswith("://-")
        ):
            return ""
        return cleaned

    @classmethod
    def _is_valid_url_host(cls, host: str) -> bool:
        if not host:
            return False
        if cls.URL_PLACEHOLDER_RE.search(host):
            return False
        if host == "localhost":
            return True
        if cls.IPV4_EXACT_RE.fullmatch(host):
            return True
        return bool(cls.HOSTNAME_RE.fullmatch(host))

    @classmethod
    def _is_source_repo_reference_url(cls, host: str, path: str) -> bool:
        if host not in cls.REPO_REFERENCE_HOSTS:
            return False

        path_parts = [segment for segment in path.strip("/").split("/") if segment]
        if not path_parts:
            return False

        # GitHub repository references:
        # /<owner>/<repo>/(issues|pull|pulls|blob|tree|commit|commits|compare|wiki|releases)/...
        if host in {"github.com", "www.github.com"}:
            if len(path_parts) >= 3 and path_parts[2] in {
                "issues",
                "issue",
                "pull",
                "pulls",
                "blob",
                "tree",
                "commit",
                "commits",
                "compare",
                "wiki",
                "releases",
            }:
                return True
            return False

        # GitLab references:
        # /<group>/<project>/-/(issues|merge_requests|blob|tree|commit|commits|releases)/...
        if host == "gitlab.com":
            if len(path_parts) >= 4 and path_parts[2] == "-" and path_parts[3] in {
                "issues",
                "merge_requests",
                "blob",
                "tree",
                "commit",
                "commits",
                "releases",
            }:
                return True
            return False

        # Bitbucket references:
        # /<workspace>/<repo>/(issues|pull-requests|src|commits|branches)/...
        if host == "bitbucket.org":
            if len(path_parts) >= 3 and path_parts[2] in {
                "issues",
                "pull-requests",
                "src",
                "commits",
                "branches",
            }:
                return True
            return False

        return False

    @staticmethod
    def _to_base_url(url: str) -> str:
        """Return URL origin as scheme://host[:port], dropping path/query/fragment."""
        try:
            parsed = urlparse(str(url).strip())
        except ValueError:
            return ""

        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        if not scheme or not host:
            return ""

        netloc = host
        default_ports = {"http": 80, "https": 443, "ws": 80, "wss": 443}
        if parsed.port and parsed.port != default_ports.get(scheme):
            netloc = f"{host}:{parsed.port}"
        return f"{scheme}://{netloc}"

    @classmethod
    def _collapse_urls_to_common_bases(cls, urls: set[str]) -> list[str]:
        """Normalize to base URLs first, then keep unique origins only."""
        unique_bases = {
            base
            for base in (cls._to_base_url(url) for url in urls)
            if base
        }
        return sorted(unique_bases)

    @staticmethod
    def _snippet_at_index(text: str, index: int, radius: int = 50) -> str:
        start = max(0, index - radius)
        end = min(len(text), index + radius)
        return text[start:end]

    @classmethod
    def _is_probable_version_ip(cls, ip_text: str, searchable_text: str, match_start: int) -> bool:
        """Heuristic guard against dotted-version false positives (e.g. 1.1.1.1)."""
        try:
            parts = [int(part) for part in ip_text.split(".")]
        except ValueError:
            return False

        # We only evaluate IPv4 dotted quads here.
        if len(parts) != 4:
            return False

        if ip_text in cls.KNOWN_PUBLIC_SERVICE_IPS:
            return False
        if parts[0] == 0:
            return True

        lowered = searchable_text.lower()
        ip_lower = ip_text.lower()
        snippet = cls._snippet_at_index(lowered, match_start, radius=60)
        if any(hint in snippet for hint in cls.OID_CONTEXT_HINTS):
            return True
        if any(hint in snippet for hint in cls.VERSION_CONTEXT_HINTS):
            return True
        if any(hint in snippet for hint in cls.NETWORK_CONTEXT_HINTS):
            return False
        if cls.IP_CONTEXT_RE.search(snippet):
            return False

        before = lowered[max(0, match_start - 16):match_start]
        if re.search(r"(?:\bversion\b|\bver\b)\s*$", before):
            return True
        if match_start > 0 and lowered[match_start - 1] in {"/", "v"}:
            return True

        match_end = match_start + len(ip_text)
        if match_end < len(lowered):
            trailing = lowered[match_end]
            if trailing in {"-", "_"} or trailing.isalnum():
                return True

        if all(part < 10 for part in parts) and ip_text not in cls.KNOWN_PUBLIC_SERVICE_IPS:
            return True
        if all(part <= 20 for part in parts):
            return True
        return bool(re.search(rf"{re.escape(ip_lower)}[a-z]", snippet))

    @classmethod
    def _is_valuable_secret_evidence(cls, title: str, evidence: str) -> bool:
        """Apply strict heuristics so only likely-sensitive values are reported."""
        text = evidence.strip()
        lowered = text.lower()
        if len(text) < 10:
            return False

        # Strongly-typed key patterns are already high signal.
        if title in {"AWS Access Key", "Google API Key", "Stripe Live Key", "GitHub Token"}:
            return True

        # JWT evidence must look like a token and not only structural fragments.
        if title == "JWT Token":
            return bool(re.search(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", text))

        if title == "Bearer/Auth Header Token":
            token_match = re.search(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]+=*)", text)
            if not token_match:
                return False
            token = token_match.group(1)
            return len(token) >= 20 and cls._entropy(token) >= 3.2

        # Generic credential assignment: evaluate extracted value quality.
        value_match = cls.SECRET_VALUE_RE.search(text)
        if not value_match:
            return False
        value = value_match.group(1).strip()
        low_val = value.lower()
        if low_val in cls.NOISE_SECRET_VALUES:
            return False
        if value.startswith(("@string/", "@xml/", "BuildConfig.", "${", "#{")):
            return False
        if re.fullmatch(r"[0-9a-f]{6,}", low_val):
            return False
        if len(value) < 8:
            return False
        if cls._entropy(value) < 2.8 and not re.search(r"[A-Za-z].*[0-9]|[0-9].*[A-Za-z]", value):
            return False
        return True

    @classmethod
    def _extract_printable_strings(cls, data: bytes, max_strings: int) -> list[str]:
        strings: list[str] = []
        for idx, match in enumerate(cls.PRINTABLE_RE.finditer(data)):
            if idx >= max_strings:
                break
            token = match.group().decode("utf-8", errors="ignore").strip()
            if token:
                strings.append(token)
        return strings

    @staticmethod
    def _read_text_if_possible(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

    @staticmethod
    def _beautify_decoded_payload(payload: str) -> tuple[str, str]:
        text = str(payload)
        stripped = text.strip()
        if not stripped:
            return text, "text"

        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, (dict, list)):
                return json.dumps(parsed, indent=2, ensure_ascii=False), "json"
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        if stripped.startswith("<") and stripped.endswith(">"):
            try:
                root = ET.fromstring(stripped)
                tree = ET.ElementTree(root)
                if hasattr(ET, "indent"):
                    ET.indent(tree, space="  ")
                return ET.tostring(root, encoding="unicode"), "xml"
            except ET.ParseError:
                pass

        return text, "text"

    @classmethod
    def _decode_base64_if_interesting(cls, token: str) -> tuple[str, str] | None:
        if len(token) < 24:
            return None
        # Quick reject: low diversity tokens are mostly noise
        if len(set(token)) < 8:
            return None

        def decode_once(candidate: str) -> str | None:
            normalized = re.sub(r"\s+", "", candidate)
            if len(normalized) < 8:
                return None
            try:
                padded = normalized + "=" * ((4 - len(normalized) % 4) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
            except (ValueError, base64.binascii.Error):
                return None
            if len(decoded_bytes) < 4 or len(decoded_bytes) > cls.MAX_BASE64_DECODE_BYTES:
                return None
            decoded_text_ = decoded_bytes.decode("utf-8", errors="ignore")
            if len(decoded_text_.strip()) < 4:
                return None
            if any(ord(ch) < 32 and ch not in "\t\r\n" for ch in decoded_text_):
                return None
            return decoded_text_

        decoded_text = decode_once(token)
        if not decoded_text:
            return None

        # Recursively decode if the decoded value is itself base64-looking.
        for _ in range(cls.BASE64_MAX_DECODE_DEPTH - 1):
            candidate = re.sub(r"\s+", "", decoded_text)
            if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", candidate or ""):
                break
            next_decoded = decode_once(candidate)
            if not next_decoded or next_decoded == decoded_text:
                break
            decoded_text = next_decoded

        analysis_text = decoded_text.strip()
        printable_ratio = sum(ch.isprintable() for ch in analysis_text) / max(len(analysis_text), 1)
        if printable_ratio < 0.9:
            return None
        ascii_ratio = sum(ord(ch) < 128 for ch in analysis_text) / max(len(analysis_text), 1)
        if ascii_ratio < 0.85:
            return None
        if not re.search(r"[A-Za-z]{4,}", analysis_text):
            return None
        if cls._entropy(analysis_text) < 2.6:
            return None

        lowered = analysis_text.lower()
        formatted_text, text_format = cls._beautify_decoded_payload(analysis_text)

        # Strong indicators of valuable decoded artifacts.
        sensitive_markers = (
            "http://",
            "https://",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "authorization",
            "bearer",
            "client_secret",
            "password",
            "private_key",
            "-----begin",
            "firebase",
            "googleapis",
            "jwt",
        )
        if any(marker in lowered for marker in sensitive_markers):
            return formatted_text, text_format

        # JSON blobs are useful only when they include sensitive key names.
        try:
            parsed = json.loads(analysis_text)
            if isinstance(parsed, dict):
                keys = {str(k).lower() for k in parsed.keys()}
                interesting_keys = {
                    "token", "access_token", "refresh_token", "secret", "api_key",
                    "apikey", "password", "client_secret", "private_key",
                }
                if keys & interesting_keys:
                    return formatted_text, text_format
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        return None

    @staticmethod
    def _build_base64_entry(rel_file: str, encoded_token: str, decoded_text: str, decoded_format: str) -> dict:
        return {
            "file": rel_file,
            "format": decoded_format or "text",
            "encoded": encoded_token,
            "decoded": decoded_text,
        }

    @staticmethod
    def _snippet_around(text: str, needle: str, radius: int = 80) -> str:
        index = text.find(needle)
        if index < 0:
            return needle
        start = max(0, index - radius)
        end = min(len(text), index + len(needle) + radius)
        return " ".join(text[start:end].split())

    @staticmethod
    def _normalize_line_no_truncate(text: str) -> str:
        return " ".join(str(text).strip().split())

    @classmethod
    def _extract_unique_api_keys(cls, findings: list[Finding]) -> dict[str, dict[str, set[str]]]:
        """Collect unique API keys by type and track source files for deduped testing."""
        discovered: dict[str, dict[str, set[str]]] = {}
        key_titles = {title for title, _ in cls.API_KEY_VALUE_PATTERNS}

        for finding in findings:
            if finding.title in key_titles or finding.title == "Hardcoded Credential Assignment":
                for key_title, pattern in cls.API_KEY_VALUE_PATTERNS:
                    if finding.title not in {key_title, "Hardcoded Credential Assignment"}:
                        continue
                    for token in pattern.findall(finding.evidence):
                        if not token:
                            continue
                        key_group = discovered.setdefault(key_title, {})
                        key_group.setdefault(token, set()).add(finding.file)

            if finding.title == "Hardcoded Credential Assignment":
                for token in cls.GENERIC_API_KEY_ASSIGNMENT_RE.findall(finding.evidence):
                    value = str(token).strip()
                    if not value or value.lower() in cls.NOISE_SECRET_VALUES:
                        continue
                    generic_group = discovered.setdefault("Generic API Key", {})
                    generic_group.setdefault(value, set()).add(finding.file)

        return discovered

    @classmethod
    def _api_key_check_meta(cls, check_id: str) -> dict[str, str]:
        for entry in cls.API_KEY_CHECKLIST:
            if entry.get("id") == check_id:
                return entry
        return {"id": check_id, "cwe": "N/A", "cve": "N/A", "cvss": "N/A"}

    @staticmethod
    def _http_json_request(
        url: str,
        timeout: int = 12,
        method: str = "GET",
        payload: dict | None = None,
        headers: dict | None = None,
    ) -> tuple[int, dict, str]:
        request_headers = {"User-Agent": "Mozilla/5.0"}
        if headers:
            request_headers.update(headers)
        data = None
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")
        request = Request(
            url,
            headers=request_headers,
            data=data,
            method=method.upper(),
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
                payload = json.loads(body) if body.strip() else {}
                return response.getcode(), payload, ""
        except HTTPError as error:
            try:
                payload = json.loads(error.read().decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, ValueError):
                payload = {}
            return error.code, payload, str(error)
        except (URLError, TimeoutError, OSError) as error:
            return 0, {}, str(error)

    @staticmethod
    def _init_api_report_record(key: str) -> dict:
        return {
            "key": key,
            "checklist": "hardcoded-key-exposure",
            "failed_checks": set(),
            "accessible_apis": set(),
            "tests": [],
            "poc_cmd": "",
            "poc_response": "",
        }

    @classmethod
    def _get_api_report_record(cls, records: dict[str, dict], key: str) -> dict:
        return records.setdefault(key, cls._init_api_report_record(key))

    @staticmethod
    def _append_unique(items: list[str], value: str) -> None:
        normalized = str(value).strip()
        if normalized and normalized not in items:
            items.append(normalized)

    @staticmethod
    def _json_preview(payload: dict, fallback: str = "no response body", max_len: int = 260) -> str:
        if isinstance(payload, dict) and payload:
            text = json.dumps(payload, ensure_ascii=True)
            return text if len(text) <= max_len else text[: max_len - 3] + "..."
        return fallback

    @classmethod
    def _render_api_key_report_blocks(cls, records: dict[str, dict]) -> list[str]:
        blocks: list[str] = []
        block_index = 0

        for key in sorted(records):
            record = records[key]
            tests = [test for test in record.get("tests", []) if str(test).strip()]
            # Show only entries where at least one vulnerability check succeeded.
            if not tests:
                continue

            block_index += 1
            failed_checks = sorted(record.get("failed_checks", set()))
            accessible_apis = sorted(record.get("accessible_apis", set()))
            poc_cmd = record.get("poc_cmd") or "N/A"
            poc_response = record.get("poc_response") or "N/A"

            lines = [
                f"******************** API_KEY {block_index} *********************************",
                f"KEY: {record.get('key', key)}",
                "VULNERABLE_STATUS: Vulnerable",
                f"CHECKLIST: {record.get('checklist', 'hardcoded-key-exposure')}",
                "FAILED_CHECKS:",
            ]

            if failed_checks:
                for failed_check in failed_checks:
                    lines.append(f"        - {failed_check}")
            else:
                lines.append("        - none")

            lines.append("ACCESSIBLE_APIS:")
            if accessible_apis:
                for api in accessible_apis:
                    lines.append(f"        - {api}")
            else:
                lines.append("        - none")

            lines.append("TEST_CONDUCTED:")
            for test_name in tests:
                lines.append(f"        - {test_name}")

            lines.append(f"POC: {poc_cmd}")
            lines.append(f"     {poc_response}")
            lines.append("************************************************************************")
            blocks.append("\n".join(lines))

        return blocks

    def _assess_google_api_keys(
        self,
        google_keys: dict[str, set[str]],
        report_records: dict[str, dict],
    ) -> list[Finding]:
        if not google_keys:
            return []

        findings: list[Finding] = []
        restriction_meta = self._api_key_check_meta("restriction-controls")
        scope_meta = self._api_key_check_meta("least-privilege-api-scope")
        quota_meta = self._api_key_check_meta("quota-and-billing-abuse")

        for key in sorted(google_keys):
            masked_key = self.mask_secret(key)
            accessible_apis: list[str] = []
            restriction_detected = False
            invalid_key = False
            successful_tests: list[dict] = []
            test_cases = [
                {"name": name, "url": template.format(key=key), "method": "GET", "payload": None}
                for name, template in self.GOOGLE_API_TEST_ENDPOINTS
            ]
            test_cases.extend(
                [
                    {
                        "name": "firebase_identitytoolkit_lookup",
                        "url": f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={key}",
                        "method": "POST",
                        "payload": {"idToken": "invalid"},
                    },
                    {
                        "name": "cloud_translate_languages",
                        "url": f"https://translation.googleapis.com/language/translate/v2/languages?key={key}",
                        "method": "GET",
                        "payload": None,
                    },
                ]
            )

            for test_case in test_cases:
                test_name = str(test_case["name"])
                url = str(test_case["url"])
                method = str(test_case["method"])
                payload_body = test_case.get("payload")
                http_code, payload, request_error = self._http_json_request(
                    url,
                    method=method,
                    payload=payload_body if isinstance(payload_body, dict) else None,
                )
                error_message = self.extract_google_error(payload, request_error)
                normalized_error = error_message.lower()

                if "api key" in normalized_error and "invalid" in normalized_error:
                    invalid_key = True
                if any(marker in normalized_error for marker in self.GOOGLE_RESTRICTION_MARKERS):
                    restriction_detected = True

                if test_name == "maps_geocoding":
                    api_status = str(payload.get("status", "")).upper() if isinstance(payload, dict) else ""
                    success = api_status in {"OK", "ZERO_RESULTS"}
                elif test_name == "youtube_data":
                    success = isinstance(payload, dict) and "error" not in payload and "kind" in payload
                elif test_name == "firebase_identitytoolkit_lookup":
                    firebase_markers = ("invalid_id_token", "missing_id_token", "user_not_found")
                    success = any(marker in normalized_error for marker in firebase_markers) or bool(
                        isinstance(payload, dict) and payload.get("users")
                    )
                elif test_name == "cloud_translate_languages":
                    success = (
                        isinstance(payload, dict)
                        and isinstance(payload.get("data"), dict)
                        and isinstance(payload.get("data", {}).get("languages"), list)
                    )
                else:
                    success = False

                if success:
                    accessible_apis.append(test_name)
                    successful_tests.append(
                        {
                            "name": test_name,
                            "url": url,
                            "method": method,
                            "request_payload": payload_body if isinstance(payload_body, dict) else None,
                            "response_payload": payload if isinstance(payload, dict) else {},
                            "http_code": http_code,
                        }
                    )

            vulnerable = False
            failed_checks: set[str] = set()
            if not invalid_key and accessible_apis:
                if not restriction_detected:
                    vulnerable = True
                    failed_checks.update({"restriction-controls", "quota-and-billing-abuse"})
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Missing Restriction Controls",
                            severity="high",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=restriction-controls "
                                f"CWE={restriction_meta['cwe']} CVE={restriction_meta['cve']} "
                                f"CVSS={restriction_meta['cvss']}"
                            ),
                        )
                    )
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Potential Quota/Billing Abuse",
                            severity="medium",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=quota-and-billing-abuse "
                                f"CWE={quota_meta['cwe']} CVE={quota_meta['cve']} "
                                f"CVSS={quota_meta['cvss']}"
                            ),
                        )
                    )

                if len(accessible_apis) > 1:
                    vulnerable = True
                    failed_checks.add("least-privilege-api-scope")
                    findings.append(
                        Finding(
                            category="api_key_exposure",
                            title="Google API Key Overly Broad API Scope",
                            severity="medium",
                            file="google_api_key_check",
                            evidence=(
                                f"key={masked_key} accessible_apis={','.join(accessible_apis)} "
                                "checklist=least-privilege-api-scope "
                                f"CWE={scope_meta['cwe']} CVE={scope_meta['cve']} "
                                f"CVSS={scope_meta['cvss']}"
                            ),
                        )
                    )

            if not vulnerable:
                continue

            record = self._get_api_report_record(report_records, key)
            record["failed_checks"].update(failed_checks)
            record["accessible_apis"].update(accessible_apis)

            for test_result in successful_tests:
                self._append_unique(
                    record["tests"],
                    f"google-live-api-validation::{test_result['name']}",
                )

            if successful_tests:
                first_success = successful_tests[0]
                method = str(first_success["method"]).upper()
                url = str(first_success["url"])
                request_payload = first_success.get("request_payload")
                if method == "POST" and isinstance(request_payload, dict):
                    payload_preview = json.dumps(request_payload, ensure_ascii=True)
                    poc_cmd = (
                        f"curl -s -X POST \"{url}\" "
                        f"-H \"Content-Type: application/json\" -d '{payload_preview}'"
                    )
                else:
                    poc_cmd = f"curl -s \"{url}\""
                poc_response = self._json_preview(
                    first_success.get("response_payload", {}),
                    fallback=f"HTTP {first_success.get('http_code', 0)}",
                )
                if not record["poc_cmd"] or str(record["poc_cmd"]).startswith("grep -R"):
                    record["poc_cmd"] = poc_cmd
                    record["poc_response"] = poc_response

        return self._dedupe_findings(findings)

    def _assess_cloud_tokens(
        self,
        key_type: str,
        keys: dict[str, set[str]],
        endpoint: str,
        auth_header: str,
        success_predicate: callable,
        title: str,
        test_label: str,
        report_records: dict[str, dict],
    ) -> list[Finding]:
        findings: list[Finding] = []
        exposure_meta = self._api_key_check_meta("hardcoded-key-exposure")

        for key in sorted(keys):
            source_files = keys.get(key, set())
            masked_key = self.mask_secret(key)
            http_code, payload, request_error = self._http_json_request(
                endpoint,
                headers={"Authorization": f"{auth_header} {key}"},
            )
            error_message = self.extract_google_error(payload, request_error)
            is_vulnerable = success_predicate(http_code, payload)
            if not is_vulnerable:
                continue

            findings.append(
                Finding(
                    category="api_key_exposure",
                    title=title,
                    severity="high",
                    file="cloud_token_check",
                    evidence=(
                        f"key={masked_key} key_type={key_type} source_occurrences={len(source_files)} "
                        f"checklist=cloud-token-validation CWE={exposure_meta['cwe']} "
                        f"CVE={exposure_meta['cve']} CVSS={exposure_meta['cvss']}"
                    ),
                )
            )
            record = self._get_api_report_record(report_records, key)
            record["failed_checks"].add("cloud-token-validation")
            record["accessible_apis"].add(test_label)
            self._append_unique(record["tests"], test_label)

            poc_cmd = (
                f"curl -s \"{endpoint}\" "
                f"-H \"Authorization: {auth_header} {key}\""
            )
            poc_response = self._json_preview(
                payload,
                fallback=self.clean_line(error_message or f"HTTP {http_code}", max_len=220),
            )
            if not record["poc_cmd"] or str(record["poc_cmd"]).startswith("grep -R"):
                record["poc_cmd"] = poc_cmd
                record["poc_response"] = poc_response

        return findings

    def _assess_discovered_api_keys(self, hardcoded_findings: list[Finding]) -> tuple[list[Finding], list[str]]:
        discovered_keys = self._extract_unique_api_keys(hardcoded_findings)
        if not discovered_keys:
            return [], []

        findings: list[Finding] = []
        report_records: dict[str, dict] = {}
        exposure_meta = self._api_key_check_meta("hardcoded-key-exposure")

        for key_type in sorted(discovered_keys):
            key_map = discovered_keys[key_type]
            for key_value in sorted(key_map):
                source_files = key_map[key_value]
                masked_key = self.mask_secret(key_value)
                severity = "medium" if key_type == "Generic API Key" else "high"
                findings.append(
                    Finding(
                        category="api_key_exposure",
                        title=f"{key_type} Hardcoded in Application Package",
                        severity=severity,
                        file="api_key_checklist",
                        evidence=(
                            f"key={masked_key} key_type={key_type} source_occurrences={len(source_files)} "
                            "checklist=hardcoded-key-exposure "
                            f"CWE={exposure_meta['cwe']} CVE={exposure_meta['cve']} "
                            f"CVSS={exposure_meta['cvss']}"
                        ),
                    )
                )
                record = self._get_api_report_record(report_records, key_value)
                record["failed_checks"].add("hardcoded-key-exposure")
                self._append_unique(
                    record["tests"],
                    "static-hardcoded-key-detection",
                )
                first_file = sorted(source_files)[0] if source_files else "source_file_unknown"
                source_preview = ", ".join(sorted(source_files)[:3]) if source_files else "none"
                record["poc_cmd"] = (
                    f"grep -R --line-number \"{key_value}\" \"{first_file}\""
                    if not record["poc_cmd"]
                    else record["poc_cmd"]
                )
                record["poc_response"] = (
                    f"key_type={key_type}; source_occurrences={len(source_files)}; "
                    f"sources={source_preview}"
                    if not record["poc_response"]
                    else record["poc_response"]
                )

        google_findings = self._assess_google_api_keys(
            discovered_keys.get("Google API Key", {}),
            report_records,
        )
        findings.extend(google_findings)

        github_findings = self._assess_cloud_tokens(
            key_type="GitHub Token",
            keys=discovered_keys.get("GitHub Token", {}),
            endpoint="https://api.github.com/user",
            auth_header="token",
            success_predicate=lambda code, payload: (
                code == 200 and isinstance(payload, dict) and bool(payload.get("login"))
            ),
            title="GitHub Token Grants Cloud API Access",
            test_label="github-user-api-validation",
            report_records=report_records,
        )
        findings.extend(github_findings)

        stripe_findings = self._assess_cloud_tokens(
            key_type="Stripe Live Key",
            keys=discovered_keys.get("Stripe Live Key", {}),
            endpoint="https://api.stripe.com/v1/account",
            auth_header="Bearer",
            success_predicate=lambda code, payload: (
                code == 200 and isinstance(payload, dict) and bool(payload.get("id"))
            ),
            title="Stripe Live Key Grants Cloud API Access",
            test_label="stripe-account-api-validation",
            report_records=report_records,
        )
        findings.extend(stripe_findings)
        report_lines = self._render_api_key_report_blocks(report_records)

        return self._dedupe_findings(findings), report_lines

    def _scan_text_for_indicators(self, text: str, rel_file: str) -> tuple[list[Finding], list[Finding]]:
        lowered = text.lower()
        risks: list[Finding] = []
        controls: list[Finding] = []

        for category, title, severity, needles in self.RISK_INDICATORS:
            for needle in needles:
                n = needle.lower()
                if n in lowered:
                    risks.append(
                        Finding(
                            category=category,
                            title=title,
                            severity=severity,
                            file=rel_file,
                            evidence=self.clean_line(self._snippet_around(lowered, n)),
                        )
                    )
                    break

        # Regex-based detections for issues that are easy to miss in simple string matching.
        for category, title, severity, pattern in self.ADVANCED_RISK_REGEX:
            match = pattern.search(text)
            if match:
                snippet = self.clean_line(self._snippet_around(text, match.group(0)))
                risks.append(
                    Finding(
                        category=category,
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=snippet,
                    )
                )

        for category, title, severity, needles in self.CONTROL_INDICATORS:
            for needle in needles:
                n = needle.lower()
                if n in lowered:
                    controls.append(
                        Finding(
                            category=category,
                            title=title,
                            severity=severity,
                            file=rel_file,
                            evidence=self.clean_line(self._snippet_around(lowered, n)),
                        )
                    )
                    break

        return risks, controls

    def _scan_single_file(self, file_path: Path, root: Path) -> dict:
        rel_file = self._safe_relpath(file_path, root)
        suffix = file_path.suffix.lower()

        result = {
            "file": rel_file,
            "urls": set(),
            "ips": set(),
            "hardcoded": [],
            "base64": [],
            "risk_findings": [],
            "control_findings": [],
            "bytes_scanned": 0,
            "skipped": False,
        }

        try:
            stat = file_path.stat()
        except OSError:
            result["skipped"] = True
            return result

        # Skip very large assets/binaries to keep scans responsive and memory-safe.
        if suffix in self.BINARY_SKIP_EXTENSIONS and stat.st_size > self.MAX_FILE_SIZE_BYTES:
            result["skipped"] = True
            return result

        if stat.st_size > self.MAX_FILE_SIZE_BYTES:
            result["skipped"] = True
            return result

        try:
            data = file_path.read_bytes()
        except OSError:
            result["skipped"] = True
            return result

        result["bytes_scanned"] = len(data)

        # Build searchable corpus from decoded text + extracted printable strings.
        # This avoids external string tools and keeps one-pass analysis per file.
        text_parts: list[str] = []
        if suffix in self.TEXT_EXTENSIONS:
            try:
                text_parts.append(data.decode("utf-8", errors="ignore"))
            except Exception:
                pass

        printable = self._extract_printable_strings(data, self.MAX_STRINGS_PER_FILE)
        if printable:
            text_parts.append("\n".join(printable))

        if not text_parts:
            return result

        searchable = "\n".join(text_parts)
        if len(searchable) > self.MAX_TEXT_CHARS_PER_FILE:
            searchable = searchable[: self.MAX_TEXT_CHARS_PER_FILE]

        # URLs/IPs: extracted first because they are cheap and high-signal.
        for match in self.URL_RE.findall(searchable):
            if self._is_valuable_url(match):
                canonical_url = self._canonicalize_url(match)
                if canonical_url:
                    result["urls"].add(canonical_url)

        for match_obj in self.IP_RE.finditer(searchable):
            match = match_obj.group(0)
            try:
                ip_obj = ipaddress.ip_address(match)
                if (
                    not ip_obj.is_loopback
                    and not ip_obj.is_multicast
                    and not ip_obj.is_unspecified
                    and not ip_obj.is_reserved
                ):
                    if self._is_probable_version_ip(match, searchable, match_obj.start()):
                        continue
                    result["ips"].add(match)
            except ValueError:
                continue

        # Hardcoded secret patterns are reported with contextual evidence.
        for title, severity, pattern in self.SECRET_PATTERNS:
            for m in pattern.finditer(searchable):
                evidence = self._normalize_line_no_truncate(m.group(0))
                if not self._is_valuable_secret_evidence(title, evidence):
                    continue
                result["hardcoded"].append(
                    Finding(
                        category="hardcoded_secret",
                        title=title,
                        severity=severity,
                        file=rel_file,
                        evidence=evidence,
                    )
                )

        # Base64 decode is intentionally filtered to reduce noisy gibberish.
        seen_b64 = set()
        for token in self.BASE64_TOKEN_RE.findall(searchable):
            if token in seen_b64:
                continue
            seen_b64.add(token)
            decoded_payload = self._decode_base64_if_interesting(token)
            if decoded_payload:
                decoded_text, decoded_format = decoded_payload
                result["base64"].append(
                    self._build_base64_entry(rel_file, token, decoded_text, decoded_format)
                )

        # Any cleartext backend endpoint found in source is a high-value network risk signal.
        for url in result["urls"]:
            if url.lower().startswith("http://"):
                result["risk_findings"].append(
                    Finding(
                        category="network_security",
                        title="Potential Cleartext Backend Endpoint",
                        severity="medium",
                        file=rel_file,
                        evidence=self._normalize_line_no_truncate(url),
                    )
                )

        # Integrity and anti-tamper detections are source-level static heuristics.
        risks, controls = self._scan_text_for_indicators(searchable, rel_file)
        result["risk_findings"].extend(risks)
        result["control_findings"].extend(controls)

        return result

    # ------------------------------------------------------------------
    # Platform-specific metadata checks
    # ------------------------------------------------------------------

    def _scan_android_manifest(self, root: Path) -> tuple[list[Finding], list[Finding]]:
        manifest = root / "AndroidManifest.xml"
        if not manifest.exists():
            return [], []

        text = self._read_text_if_possible(manifest)
        if not text:
            # Binary AXML (zip fallback without apktool) may not be parseable here.
            return [], []

        rel = self._safe_relpath(manifest, root)
        risks: list[Finding] = []
        controls: list[Finding] = []

        # Manifest-level posture checks are explicit and easy to triage.
        if 'android:debuggable="true"' in text:
            risks.append(Finding("debugging", "Manifest Debuggable Enabled", "high", rel, 'android:debuggable="true"'))
        if 'android:allowBackup="true"' in text:
            risks.append(Finding("backup", "Manifest Backup Enabled", "medium", rel, 'android:allowBackup="true"'))
        if 'android:usesCleartextTraffic="true"' in text:
            risks.append(Finding("network_security", "Manifest Cleartext Traffic Enabled", "high", rel, 'android:usesCleartextTraffic="true"'))

        # Exported components are flagged, with higher severity when no permission is set.
        exported_pattern = re.compile(
            r"<(activity|service|receiver|provider)\b[^>]*android:exported=\"true\"[^>]*>",
            re.IGNORECASE,
        )
        for m in exported_pattern.finditer(text):
            snippet = self._normalize_line_no_truncate(m.group(0))
            sev = "high" if "android:permission" not in snippet.lower() else "medium"
            title = "Exported Component Without Permission" if sev == "high" else "Exported Component"
            risks.append(Finding("component_exposure", title, sev, rel, snippet))

        # Positive control: network security config is often used for TLS restrictions/pinning setup
        if 'android:networkSecurityConfig=' in text:
            controls.append(
                Finding("pinning", "Network Security Config Declared", "info", rel, "android:networkSecurityConfig")
            )

        return risks, controls

    def _scan_ios_plist(self, root: Path) -> tuple[list[Finding], list[Finding]]:
        plist_candidates = [p for p in root.rglob("Info.plist") if p.is_file()]
        if not plist_candidates:
            return [], []

        risks: list[Finding] = []
        controls: list[Finding] = []

        # Cap to a few plist files to avoid duplicate noise on large IPA bundles.
        for plist_path in plist_candidates[:3]:
            rel = self._safe_relpath(plist_path, root)
            try:
                payload = plistlib.loads(plist_path.read_bytes())
            except Exception:
                # Not parseable; fallback string scan
                text = self._read_text_if_possible(plist_path)
                if "NSAllowsArbitraryLoads" in text:
                    risks.append(Finding("network_security", "ATS Arbitrary Loads Detected", "high", rel, "NSAllowsArbitraryLoads"))
                continue

            ats = payload.get("NSAppTransportSecurity", {})
            if isinstance(ats, dict):
                if bool(ats.get("NSAllowsArbitraryLoads")):
                    risks.append(Finding("network_security", "ATS Arbitrary Loads Enabled", "high", rel, "NSAllowsArbitraryLoads=true"))
                else:
                    controls.append(Finding("network_security", "ATS Policy Present", "info", rel, "NSAppTransportSecurity present"))

            url_types = payload.get("CFBundleURLTypes")
            if url_types:
                controls.append(Finding("deeplink", "Custom URL Schemes Declared", "info", rel, "CFBundleURLTypes present"))

        return risks, controls

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
        unique = {}
        for finding in findings:
            key = (finding.category, finding.title, finding.severity, finding.file, finding.evidence)
            unique[key] = finding
        return list(unique.values())

    @staticmethod
    def _write_lines(path: Path, lines: Iterable[str]) -> int:
        filtered_lines = [str(line).rstrip("\n") for line in lines if str(line).strip()]
        if not filtered_lines:
            return 0

        unique_lines = list(dict.fromkeys(filtered_lines))

        count = 0
        with path.open("w", encoding="utf-8") as fh:
            for line in unique_lines:
                fh.write(f"{line}\n")
                count += 1
        return count

    def _write_findings_report(self, path: Path, findings: list[Finding]) -> int:
        rows = []
        seen_values = set()
        for finding in findings:
            # Keep one entry per finding value to prevent duplicates across files.
            value_key = (finding.category.lower(), finding.title.lower(), finding.evidence.strip().lower())
            if value_key in seen_values:
                continue
            seen_values.add(value_key)
            rows.append(
                f"[{finding.severity.upper()}] {finding.category} | {finding.title} | {finding.file} | {finding.evidence}"
            )
        return self._write_lines(path, rows)

    @staticmethod
    def _write_api_check_report(path: Path, lines: Iterable[str]) -> int:
        """Write API key checklist blocks in report format."""
        blocks = [str(line).strip("\n") for line in lines if str(line).strip()]
        if not blocks:
            return 0

        unique_blocks = list(dict.fromkeys(blocks))

        with path.open("w", encoding="utf-8") as fh:
            for index, block in enumerate(unique_blocks, 1):
                fh.write(f"{block}\n")
                if index < len(unique_blocks):
                    fh.write("\n")
        return len(unique_blocks)

    @staticmethod
    def _write_base64_report(path: Path, entries: Iterable[dict]) -> int:
        grouped: dict[tuple[str, str, str], set[str]] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            encoded_text = str(entry.get("encoded", "")).strip()
            decoded_text = str(entry.get("decoded", "")).strip("\n")
            decoded_format = str(entry.get("format", "text") or "text").strip()
            source_file = str(entry.get("file", "")).strip()
            if not encoded_text or not decoded_text or not source_file:
                continue
            key = (encoded_text, decoded_text, decoded_format)
            grouped.setdefault(key, set()).add(source_file)

        if not grouped:
            return 0

        sorted_entries = sorted(
            grouped.items(),
            key=lambda item: (
                min(item[1]) if item[1] else "",
                item[0][2],
                item[0][0][:40],
            ),
        )

        with path.open("w", encoding="utf-8") as fh:
            for encoded_decoded, files in sorted_entries:
                encoded_text, decoded_text, decoded_format = encoded_decoded
                ordered_files = sorted(files)

                fh.write("===== BASE64 FINDING START =====\n\n")
                fh.write("FILE:\n")
                for file_name in ordered_files:
                    fh.write(f"  - {file_name}\n")
                fh.write(f"FILE COUNT: {len(ordered_files)}\n")
                fh.write(f"FORMAT: {decoded_format}\n")
                fh.write("ENCODED:\n")
                fh.write(f"  {encoded_text}\n")
                fh.write("DECODED:\n")
                decoded_lines = decoded_text.splitlines() or [decoded_text]
                for line in decoded_lines:
                    fh.write(f"  {line}\n")
                fh.write("\n")
                fh.write("===== BASE64 FINDING END =====\n\n")
        return len(sorted_entries)

    @classmethod
    def _build_severity_score(cls, findings: list[Finding]) -> dict:
        """Build a normalized risk score from severity-weighted findings."""
        severity_counts: dict[str, int] = {key: 0 for key in cls.SEVERITY_WEIGHTS}
        weighted_total = 0

        for finding in findings:
            sev = finding.severity.lower()
            if sev not in severity_counts:
                sev = "info"
            severity_counts[sev] += 1
            weighted_total += cls._severity_weight(sev)

        # Normalize to 0-100; this keeps output readable even for very large apps.
        risk_score = min(100, int(round(weighted_total * 2.5)))
        security_posture_score = max(0, 100 - risk_score)

        if risk_score >= 85:
            risk_band = "critical"
        elif risk_score >= 65:
            risk_band = "high"
        elif risk_score >= 40:
            risk_band = "medium"
        elif risk_score >= 20:
            risk_band = "low"
        else:
            risk_band = "informational"

        return {
            "risk_score": risk_score,
            "security_posture_score": security_posture_score,
            "risk_band": risk_band,
            "weighted_total": weighted_total,
            "severity_breakdown": severity_counts,
        }

    @staticmethod
    def _cleanup_previous_reports(output_dir: str, app_name: str, platform: str) -> None:
        """Remove stale report files for a package so each run is deterministic."""
        base = Path(output_dir)
        patterns = [
            f"{app_name}_{platform}_*.txt",
            f"{app_name}_{platform}_*.json",
            f"{app_name}_nuclei_*_results.txt",
        ]
        for pattern in patterns:
            for path in base.glob(pattern):
                try:
                    path.unlink()
                except OSError:
                    continue

    def _console_summary(self, summary: dict) -> None:
        scoring = summary.get("scoring", {})
        self.print_success_message(
            (
                "Mobile static analysis summary: "
                f"files={summary['files_scanned']} skipped={summary['files_skipped']} "
                f"urls={summary['url_count']} ips={summary['ip_count']} "
                f"hardcoded={summary['hardcoded_count']} "
                f"api_key_checks={summary.get('api_key_assessment_count', 0)} "
                f"api_key_issues={summary.get('api_key_issue_count', 0)} "
                f"base64={summary['base64_count']} "
                f"risk_findings={summary['risk_count']} integrity_controls={summary['control_count']}"
            )
        )
        if scoring:
            self.print_info_message(
                "Risk scoring: "
                f"risk_score={scoring.get('risk_score')} "
                f"security_posture_score={scoring.get('security_posture_score')} "
                f"band={scoring.get('risk_band')}"
            )

        if summary["top_risks"]:
            self.print_info_message("Top risk findings:")
            for row in summary["top_risks"]:
                print(f"  - {row}")

        if summary["top_controls"]:
            self.print_info_message("Detected integrity/security controls:")
            for row in summary["top_controls"]:
                print(f"  - {row}")

    # ------------------------------------------------------------------
    # Optional nuclei scanning
    # ------------------------------------------------------------------

    @staticmethod
    def _dedupe_output_file(path: Path) -> int:
        if not path.exists():
            return 0
        lines = []
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                value = line.strip()
                if value:
                    lines.append(value)
        if not lines:
            path.unlink(missing_ok=True)
            return 0

        unique_lines = list(dict.fromkeys(lines))
        with path.open("w", encoding="utf-8") as fh:
            for line in unique_lines:
                fh.write(f"{line}\n")
        return len(unique_lines)

    @classmethod
    def _is_nuclei_template_sync_fresh(cls, template_dir: Path) -> bool:
        marker = template_dir / ".last_sync_epoch"
        if not marker.exists():
            return False
        if not (template_dir / "Keys").exists():
            return False
        try:
            last_sync = int(marker.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            return False
        return (int(time.time()) - last_sync) < cls.NUCLEI_TEMPLATE_SYNC_TTL_SECONDS

    @staticmethod
    def _mark_nuclei_template_sync(template_dir: Path) -> None:
        marker = template_dir / ".last_sync_epoch"
        try:
            marker.write_text(str(int(time.time())), encoding="utf-8")
        except OSError:
            pass

    def install_nuclei_template(self, install_path: str) -> bool:
        """Ensure mobile nuclei templates exist locally and are updated."""
        template_dir = Path(install_path).resolve()
        repository = "https://github.com/optiv/mobile-nuclei-templates.git"

        # Avoid repeated pulls when scanning multiple applications in one run.
        if self._nuclei_templates_synced and template_dir.exists():
            return True

        if not shutil.which("git"):
            self.print_error_message("git is required to update nuclei templates")
            return False

        if template_dir.exists():
            if (template_dir / ".git").exists():
                if self._is_nuclei_template_sync_fresh(template_dir):
                    self.print_info_message(
                        "Using cached mobile nuclei templates (recent sync found)",
                        file_path=str(template_dir),
                    )
                    self._nuclei_templates_synced = True
                    return True
                self.print_info_message(
                    "Updating mobile nuclei templates to latest version",
                    file_path=str(template_dir),
                )
                fetch = self.execute_command(["git", "-C", str(template_dir), "fetch", "--all", "--prune"])
                pull = self.execute_command(["git", "-C", str(template_dir), "pull", "--ff-only"])
                if fetch.returncode != 0 or pull.returncode != 0:
                    error = pull.stderr.strip() or fetch.stderr.strip() or "Unknown git error"
                    self.print_warning_message(
                        "Failed to update nuclei templates; continuing with local copy.",
                        file_path=error,
                    )
                    self._mark_nuclei_template_sync(template_dir)
                    self._nuclei_templates_synced = True
                    return True
                self._mark_nuclei_template_sync(template_dir)
                self._nuclei_templates_synced = True
                return True

            self.print_warning_message(
                "Existing nuclei template directory is not a git repository; recreating.",
                file_path=str(template_dir),
            )
            try:
                shutil.rmtree(template_dir)
            except OSError as error:
                self.print_error_message("Failed to recreate nuclei template directory", exception_error=error)
                return False

        try:
            template_dir.parent.mkdir(parents=True, exist_ok=True)
        except OSError as error:
            self.print_error_message("Failed to prepare nuclei template path", exception_error=error)
            return False

        self.print_info_message(
            "Cloning latest mobile nuclei templates",
            file_path=str(template_dir),
        )
        clone = self.execute_command(["git", "clone", "--depth", "1", repository, str(template_dir)])
        if clone.returncode != 0:
            self.print_error_message("Failed to clone nuclei templates", exception_error=clone.stderr.strip())
            return False

        self._mark_nuclei_template_sync(template_dir)
        self._nuclei_templates_synced = True
        return True

    def scan_with_nuclei(self, application_folder: str, output_dir: str, platform: str) -> dict:
        results = {"keys_results": 0, "platform_results": 0, "ran": False}

        if not shutil.which("nuclei"):
            return results

        nuclei_dir = self.templates_folder
        if not self.install_nuclei_template(nuclei_dir):
            return results

        out_file = Path(output_dir) / f"{self.file_name}_nuclei_keys_results.txt"
        platform_file = Path(output_dir) / f"{self.file_name}_nuclei_{platform}_results.txt"

        # Use input list file instead of shell pipes
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".txt") as tmp:
            tmp.write(f"{application_folder}\n")
            input_file = tmp.name

        try:
            key_cmd = ["nuclei", "-silent", "-file", "-l", input_file, "-t", f"{nuclei_dir}/Keys", "-o", str(out_file)]
            key_res = self.execute_command(key_cmd)
            if key_res.returncode == 0:
                results["ran"] = True
            key_count = self._dedupe_output_file(out_file)
            if key_count > 0:
                results["keys_results"] = key_count

            if platform == "android":
                plat_cmd = [
                    "nuclei",
                    "-silent",
                    "-file",
                    "-l",
                    input_file,
                    "-t",
                    f"{nuclei_dir}/Android",
                    "-o",
                    str(platform_file),
                ]
                plat_res = self.execute_command(plat_cmd)
                if plat_res.returncode == 0:
                    results["ran"] = True
                platform_count = self._dedupe_output_file(platform_file)
                if platform_count > 0:
                    results["platform_results"] = platform_count
        finally:
            try:
                os.unlink(input_file)
            except OSError:
                pass

        return results

    # ------------------------------------------------------------------
    # Main execution flow
    # ------------------------------------------------------------------

    @CustomDecorators.measure_execution_time
    def inspect_application_files(self, application: str, test_domain: str, operating_system: str):
        try:
            if operating_system == "darwin":
                # macOS ships BSD grep; keep this for legacy helper compatibility.
                self.update_grep_cmd()

            # Resolve output root for mobile module and extract package contents.
            self.update_output_directory(test_domain)
            folder_name, extraction_method = self.decompile_application(application)

            # Store scan results in dedicated subfolder
            self.create_subfolder()
            output_prefix = f"{self.mobile_output_dir}/{self.file_name}"

            # Avoid path issues in nested extracted folders
            self.rename_folders_with_spaces(folder_name)

            platform = "android" if self.file_type == "apk" else "ios"
            basename = f"{output_prefix}_{platform}"
            # Prevent stale reports from previous scans of the same application.
            self._cleanup_previous_reports(self.mobile_output_dir, self.file_name, platform)

            root = Path(folder_name)
            all_files = [p for p in root.rglob("*") if p.is_file()]
            self.file_count = len(all_files)

            # Keep worker count bounded to avoid over-scheduling on huge apps.
            workers = max(4, min(32, (os.cpu_count() or 4) * self.THREAD_FACTOR))

            urls: set[str] = set()
            ips: set[str] = set()
            hardcoded: list[Finding] = []
            base64_entries: list[dict] = []
            risk_findings: list[Finding] = []
            control_findings: list[Finding] = []

            bytes_scanned = 0
            files_skipped = 0

            # Single-pass parallel scan: each worker extracts URLs/IPs/secrets/signals
            # from one file, then results are merged here in the main thread.
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = [executor.submit(self._scan_single_file, path, root) for path in all_files]
                for future in as_completed(futures):
                    scanned = future.result()
                    if scanned["skipped"]:
                        files_skipped += 1
                        continue

                    bytes_scanned += scanned["bytes_scanned"]
                    urls.update(scanned["urls"])
                    ips.update(scanned["ips"])
                    hardcoded.extend(scanned["hardcoded"])
                    base64_entries.extend(scanned["base64"])
                    risk_findings.extend(scanned["risk_findings"])
                    control_findings.extend(scanned["control_findings"])

            # Platform metadata checks
            if platform == "android":
                m_risks, m_controls = self._scan_android_manifest(root)
            else:
                m_risks, m_controls = self._scan_ios_plist(root)
            risk_findings.extend(m_risks)
            control_findings.extend(m_controls)

            # Dedupe all structured findings
            hardcoded = self._dedupe_findings(hardcoded)
            risk_findings = self._dedupe_findings(risk_findings)
            control_findings = self._dedupe_findings(control_findings)

            # Execute API key checklist once per unique key value.
            api_key_findings, api_key_report_lines = self._assess_discovered_api_keys(hardcoded)
            if api_key_findings:
                risk_findings.extend(api_key_findings)
                risk_findings = self._dedupe_findings(risk_findings)

            # Heuristic: if HTTPS endpoints exist but no pinning control is detected,
            # surface a low-severity visibility finding for manual verification.
            has_https_endpoint = any(url.lower().startswith("https://") for url in urls)
            has_pinning_signal = any(f.category == "pinning" for f in control_findings)
            if has_https_endpoint and not has_pinning_signal:
                risk_findings.append(
                    Finding(
                        category="pinning",
                        title="No Certificate Pinning Signal Detected (Heuristic)",
                        severity="low",
                        file="global",
                        evidence="HTTPS endpoints discovered, but no static pinning signal matched.",
                    )
                )
                risk_findings = self._dedupe_findings(risk_findings)

            # Combine direct risks with discovered hardcoded secrets for scoring/prioritization.
            combined_risk_findings = self._dedupe_findings(risk_findings + hardcoded)

            # Optional nuclei (no network cloning)
            nuclei_meta = self.scan_with_nuclei(folder_name, self.mobile_output_dir, platform)

            # Output files (lowercase names for consistency)
            urls_file = Path(f"{basename}_urls.txt")
            ips_file = Path(f"{basename}_ips.txt")
            hardcoded_file = Path(f"{basename}_hardcoded.txt")
            api_key_report_file = Path(f"{basename}_api_key_checklist.txt")
            base64_file = Path(f"{basename}_base64.txt")
            risk_file = Path(f"{basename}_integrity_findings.txt")
            control_file = Path(f"{basename}_integrity_controls.txt")
            summary_file = Path(f"{basename}_summary.json")

            sorted_urls = self._collapse_urls_to_common_bases(urls)
            sorted_ips = sorted(ips, key=lambda x: tuple(int(part) for part in x.split(".")))

            url_count = self._write_lines(urls_file, sorted_urls)
            ip_count = self._write_lines(ips_file, sorted_ips)
            hardcoded_count = self._write_findings_report(hardcoded_file, hardcoded)
            api_key_assessment_count = self._write_api_check_report(
                api_key_report_file, api_key_report_lines
            )
            base64_count = self._write_base64_report(base64_file, base64_entries)
            risk_count = self._write_findings_report(risk_file, risk_findings)
            control_count = self._write_findings_report(control_file, control_findings)
            reports = {}
            if url_count:
                reports["urls"] = str(urls_file)
            if ip_count:
                reports["ips"] = str(ips_file)
            if hardcoded_count:
                reports["hardcoded"] = str(hardcoded_file)
            if api_key_assessment_count:
                reports["api_key_checklist"] = str(api_key_report_file)
            if base64_count:
                reports["base64"] = str(base64_file)
            if risk_count:
                reports["integrity_findings"] = str(risk_file)
            if control_count:
                reports["integrity_controls"] = str(control_file)

            risk_counter = {}
            for finding in combined_risk_findings:
                key = f"{finding.title} ({finding.severity})"
                risk_counter[key] = risk_counter.get(key, 0) + 1

            control_counter = {}
            for finding in control_findings:
                key = f"{finding.title}"
                control_counter[key] = control_counter.get(key, 0) + 1

            top_risks = [f"{k}: {v}" for k, v in sorted(risk_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
            top_controls = [f"{k}: {v}" for k, v in sorted(control_counter.items(), key=lambda x: x[1], reverse=True)[:8]]
            scoring = self._build_severity_score(combined_risk_findings)

            summary = {
                "application": os.path.basename(application),
                "application_sha256": hashlib.sha256(Path(application).read_bytes()).hexdigest(),
                "platform": platform,
                "extraction_method": extraction_method,
                "output_directory": self.mobile_output_dir,
                "files_scanned": self.file_count - files_skipped,
                "files_skipped": files_skipped,
                "bytes_scanned": bytes_scanned,
                "url_count": url_count,
                "ip_count": ip_count,
                "hardcoded_count": hardcoded_count,
                "api_key_assessment_count": api_key_assessment_count,
                "api_key_issue_count": len(api_key_findings),
                "base64_count": base64_count,
                "risk_count": risk_count,
                "control_count": control_count,
                "combined_risk_count": len(combined_risk_findings),
                "top_risks": top_risks,
                "top_controls": top_controls,
                "scoring": scoring,
                "nuclei": nuclei_meta,
                "reports": reports,
            }

            summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")

            self._scan_stats = summary
            self._console_summary(summary)

            self.print_success_message(
                message="Application scanning complete, all files are located here:",
                mobile_success=self.mobile_output_dir,
            )

            self.flush_system()

        except Exception as error:
            self.print_error_message(message="Error during mobile assessment", exception_error=error)
        finally:
            self._cleanup_processes()

    def _cleanup_processes(self):
        try:
            self.flush_system("I/O")
        except Exception as error:
            self.print_error_message(message="Error during cleanup", exception_error=error)
