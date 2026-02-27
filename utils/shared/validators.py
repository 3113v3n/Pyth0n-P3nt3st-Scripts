"""
validators.py — Input validation utilities shared across all framework modules.

Uses Python's built-in ipaddress module for IP/CIDR validation instead of
hand-rolled regex, giving correct IPv4 + IPv6 support with less code.
"""

import re
import os
import ipaddress


class Validator:
    """Collection of static validation helpers."""

    # ------------------------------------------------------------------
    # IP / Network address validation
    # ------------------------------------------------------------------

    @staticmethod
    def is_valid_ip(addr: str) -> bool:
        """Return True if *addr* is a valid IPv4 or IPv6 address.

        Replaces the previous hand-rolled IPv4-only regex with the standard
        library ipaddress module for correctness and IPv6 support.

        Args:
            addr: String to validate.

        Returns:
            True if addr is a valid IP address.
        """
        # [Performance] ipaddress.ip_address() is faster and more accurate
        # than a verbose manual regex pattern.
        try:
            ipaddress.ip_address(addr)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_ip_addr(cls, addr: str) -> bool:
        """Backward-compatible alias for is_valid_ip()."""
        return cls.is_valid_ip(addr)

    @staticmethod
    def is_valid_cidr(cidr: str) -> bool:
        """Return True if *cidr* is a valid prefix length (0–32 for IPv4, 0–128 for IPv6).

        Args:
            cidr: Prefix length as a string, e.g. "24".

        Returns:
            True if the string represents a valid CIDR prefix length.
        """
        # [Performance] Direct integer comparison replaces regex.
        try:
            prefix = int(cidr)
            return 0 <= prefix <= 128
        except (ValueError, TypeError):
            return False

    @classmethod
    def validate_cidr(cls, cidr: str) -> bool:
        """Backward-compatible alias for is_valid_cidr()."""
        return cls.is_valid_cidr(cidr)

    @staticmethod
    def is_valid_ip_with_cidr(ip_address: str) -> bool:
        """Return True if *ip_address* is a valid IP address with CIDR notation.

        Accepts both IPv4 (e.g. "10.0.0.1/24") and IPv6 formats.

        Args:
            ip_address: String in IP/prefix format.

        Returns:
            True if the string is a valid network address with prefix.
        """
        # [Performance] ipaddress.ip_network() validates the full format.
        try:
            ipaddress.ip_network(ip_address, strict=False)
            return True
        except ValueError:
            return False

    @classmethod
    def validate_ip_and_cidr(cls, ip_address: str) -> bool:
        """Backward-compatible alias for is_valid_ip_with_cidr()."""
        return cls.is_valid_ip_with_cidr(ip_address)

    # ------------------------------------------------------------------
    # File / directory validation
    # ------------------------------------------------------------------

    @staticmethod
    def file_exists(filename: str) -> bool:
        """Return True if *filename* exists on the filesystem.

        Args:
            filename: Path to check.

        Returns:
            True if the path exists.
        """
        return os.path.exists(filename)

    def isfile_and_exists(self, filename: str) -> bool:
        """Return True if *filename* exists and is a regular file (not a directory).

        Args:
            filename: Path to check.

        Returns:
            True if the path exists and is a file.
        """
        return os.path.isfile(filename) and self.file_exists(filename)

    @staticmethod
    def check_folder_exists(folder_path: str) -> bool:
        """Return True if *folder_path* is an existing directory.

        Handles trailing slash issues via os.path.normpath.

        Args:
            folder_path: Directory path to check.

        Returns:
            True if the path is an existing directory.
        """
        norm_path = os.path.normpath(folder_path)
        return os.path.isdir(norm_path)

    @staticmethod
    def check_subdirectory_exists(folder_name: str, search_path: str) -> bool:
        """Return True if *folder_name* exists as a subdirectory of *search_path*.

        Args:
            folder_name: Name of the subdirectory to look for.
            search_path: Root directory to search in.

        Returns:
            True if the subdirectory is found.
        """
        for _, subfolders, _ in os.walk(search_path):
            if folder_name in subfolders:
                return True
        return False

    @staticmethod
    def find_specific_file(filename: str, search_path: str) -> str | None:
        """Search *search_path* recursively for a file named *filename*.

        Args:
            filename:    Exact filename to search for (no wildcards).
            search_path: Root directory to walk.

        Returns:
            Full path to the first match, or None if not found.
        """
        for root, _, files in os.walk(search_path):
            if filename in files:
                return os.path.join(root, filename)
        return None

    # ------------------------------------------------------------------
    # File type validation
    # ------------------------------------------------------------------

    @staticmethod
    def check_filetype(filename: str, filetype: str) -> bool:
        """Return True if *filename* ends with the given *filetype* extension.

        The check is case-insensitive and uses the actual file extension to
        avoid false positives like "malware.apk.txt" matching "apk".

        Args:
            filename: File name or path to check.
            filetype: Extension without the dot, e.g. "apk".

        Returns:
            True if the file extension matches.
        """
        pattern = re.compile(rf"\.{re.escape(filetype)}$", re.IGNORECASE)
        return bool(pattern.search(filename))

    # ------------------------------------------------------------------
    # String / domain validation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Return True if *domain* is a syntactically valid domain name.

        Args:
            domain: Domain string to validate, e.g. "example.com".

        Returns:
            True if the string matches the domain pattern.
        """
        pattern = re.compile(
            r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
        )
        return bool(pattern.match(domain))

    @staticmethod
    def get_filename_without_extension(filepath: str) -> str:
        """Return the base filename without its extension.

        Args:
            filepath: Full or relative path to the file.

        Returns:
            Filename stem, e.g. "report" for "report.xlsx".
        """
        filename_with_ext = os.path.basename(filepath)
        filename_without_ext, _ = os.path.splitext(filename_with_ext)
        return filename_without_ext

    @staticmethod
    def remove_spaces(text: str) -> str:
        """Replace all spaces in *text* with underscores.

        Args:
            text: Input string.

        Returns:
            String with spaces replaced by underscores.
        """
        return text.replace(" ", "_")
