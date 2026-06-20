"""
hash_util.py — Hash cracking and NTDS dump comparison utilities.

Fixes applied:
  1. Renamed _parts → username_parts / ntds_fields to clarify what is being split.
  2. Fixed typo _formated → formatted_username.
"""

import os

from ..shared.colors import Bcolors
from .password_output import build_grouped_password_output


class HashUtil:
    """Helpers for working with password hashes obtained during internal assessments."""

    def __init__(self):
        super().__init__()

    @staticmethod
    def _open_private_output(path: str, append: bool = False):
        """Open sensitive credential output files with 0600 permissions."""
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

    @staticmethod
    def format_username(username: str) -> str:
        """Strip the domain prefix from *username* if present.

        Converts "DOMAIN\\Username" to "Username". If no domain prefix is
        found the original string is returned unchanged.

        Args:
            username: Raw username string, possibly prefixed with a domain.

        Returns:
            Username without domain prefix.
        """
        # [Naming] Renamed _parts → username_parts to clarify the split context.
        username_parts = username.split("\\", 1)
        if len(username_parts) < 2:
            return username
        return username_parts[1]

    @staticmethod
    def get_hashes(cracked_hashes_file: str) -> dict[str, str]:
        """Read a cracked-hashes file and return a {hash: password} mapping.

        Expected line format: ``<md5hash>:<plaintext_password>``

        Args:
            cracked_hashes_file: Path to the file containing cracked hash:password pairs.

        Returns:
            Dictionary mapping each hash value to its cracked plaintext password.
        """
        cracked_hashes: dict[str, str] = {}
        with open(cracked_hashes_file, "r") as hashes:
            for line in hashes:
                if not line.strip():
                    continue
                try:
                    hash_val, password = line.strip().split(":", 1)
                    cracked_hashes[hash_val] = password
                except ValueError:
                    from handlers.messages import DisplayHandler

                    DisplayHandler._emit_message(
                        f"[-] Skipping malformed line in {cracked_hashes_file}: {line.strip()}"
                    )
        return cracked_hashes

    def compare_hash_from_dump(
        self,
        hash2compare: str,
        dump: str,
        userpass_list: str,
        emit_match_logs: bool = True,
    ) -> tuple[int, int]:
        """Cross-reference cracked hashes against an NTDS dump to build a user:password list.

        Only enabled Active Directory accounts are written to *userpass_list*.

        Args:
            hash2compare: Path to the cracked hashes file (hash:password pairs).
            dump:         Path to the NTDS dump file (secretsdump format).
            userpass_list: Output file path where matched username:password pairs are written.

        Returns:
            Tuple of (total_matches_found, enabled_users_written).
        """
        cracked_hashes = self.get_hashes(hash2compare)
        from handlers.messages import DisplayHandler

        DisplayHandler._emit_message(
            f"\n[*] Loaded {Bcolors.BOLD}{len(cracked_hashes)}{Bcolors.ENDC} cracked hashes"
        )

        matches_found = 0
        enabled_users = 0
        malformed_lines = 0
        user_password_pairs: list[tuple[str, str]] = []
        get_password = cracked_hashes.get
        format_username = self.format_username

        with open(dump, "r", encoding="utf-8", errors="replace") as dumps:
            for raw_line in dumps:
                line = raw_line.strip()
                if not line:
                    continue

                fields = line.split(":", 6)
                if len(fields) != 7:
                    malformed_lines += 1
                    continue

                username = fields[0]
                nthash = fields[3]
                status = fields[6]

                password = get_password(nthash)
                if password is None:
                    continue

                matches_found += 1
                if "Enabled" not in status:
                    continue

                formatted_username = format_username(username)
                user_password_pairs.append((formatted_username, password))
                enabled_users += 1

                if emit_match_logs:
                    from handlers.messages import DisplayHandler

                    DisplayHandler._emit_message(
                        f"{Bcolors.OKGREEN}[+]{Bcolors.ENDC} Match found: "
                        f"{Bcolors.OKCYAN}{formatted_username}{Bcolors.ENDC}:"
                        f"{Bcolors.WARNING}{password}{Bcolors.ENDC}"
                    )

        if malformed_lines:
            from handlers.messages import DisplayHandler

            DisplayHandler._emit_message(
                f"{Bcolors.WARNING}[-]{Bcolors.ENDC} Skipped "
                f"{malformed_lines} malformed dump lines"
            )

        grouped_output = build_grouped_password_output(user_password_pairs)
        with self._open_private_output(userpass_list) as pass_file:
            if grouped_output:
                pass_file.write(grouped_output)

        return matches_found, enabled_users

    def compare_hash_from_dump_collect(
        self,
        hash2compare: str,
        dump: str,
        userpass_list: str,
        emit_match_logs: bool = False,
    ) -> tuple[int, int, list[str]]:
        """Compare hashes, write enabled user:password lines, and return matched passwords."""
        cracked_hashes = self.get_hashes(hash2compare)
        from handlers.messages import DisplayHandler

        DisplayHandler._emit_message(
            f"\n[*] Loaded {Bcolors.BOLD}{len(cracked_hashes)}{Bcolors.ENDC} cracked hashes"
        )

        matches_found = 0
        enabled_users = 0
        malformed_lines = 0
        matched_passwords: list[str] = []
        user_password_pairs: list[tuple[str, str]] = []
        get_password = cracked_hashes.get
        format_username = self.format_username
        append_password = matched_passwords.append

        with open(dump, "r", encoding="utf-8", errors="replace") as dumps:
            for raw_line in dumps:
                line = raw_line.strip()
                if not line:
                    continue

                fields = line.split(":", 6)
                if len(fields) != 7:
                    malformed_lines += 1
                    continue

                username = fields[0]
                nthash = fields[3]
                status = fields[6]

                password = get_password(nthash)
                if password is None:
                    continue

                matches_found += 1
                if "Enabled" not in status:
                    continue

                formatted_username = format_username(username)
                user_password_pairs.append((formatted_username, password))
                append_password(password)
                enabled_users += 1

                if emit_match_logs:
                    from handlers.messages import DisplayHandler

                    DisplayHandler._emit_message(
                        f"{Bcolors.OKGREEN}[+]{Bcolors.ENDC} Match found: "
                        f"{Bcolors.OKCYAN}{formatted_username}{Bcolors.ENDC}:"
                        f"{Bcolors.WARNING}{password}{Bcolors.ENDC}"
                    )

        if malformed_lines:
            from handlers.messages import DisplayHandler

            DisplayHandler._emit_message(
                f"{Bcolors.WARNING}[-]{Bcolors.ENDC} Skipped "
                f"{malformed_lines} malformed dump lines"
            )

        grouped_output = build_grouped_password_output(user_password_pairs)
        with self._open_private_output(userpass_list) as pass_file:
            if grouped_output:
                pass_file.write(grouped_output)

        return matches_found, enabled_users, matched_passwords
