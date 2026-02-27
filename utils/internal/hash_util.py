"""
hash_util.py — Hash cracking and NTDS dump comparison utilities.

Fixes applied:
  1. Renamed _parts → username_parts / ntds_fields to clarify what is being split.
  2. Fixed typo _formated → formatted_username.
"""

from ..shared.colors import Bcolors


class HashUtil:
    """Helpers for working with password hashes obtained during internal assessments."""

    def __init__(self):
        super().__init__()

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
                    print(f"[-] Skipping malformed line in {cracked_hashes_file}: {line.strip()}")
        return cracked_hashes

    def compare_hash_from_dump(
        self,
        hash2compare: str,
        dump: str,
        userpass_list: str,
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
        print(
            f"[*] Loaded {Bcolors.BOLD}{len(cracked_hashes)}{Bcolors.ENDC} cracked hashes"
        )

        matches_found = 0
        enabled_users = 0

        with open(dump, "r") as dumps, open(userpass_list, "a") as pass_file:
            for line in dumps:
                if not line.strip():
                    continue

                # Expected NTDS dump format (secretsdump):
                # Guest:501:aad3b435b51404eeaad3b435:31d6cfe0d16ae::: (status=Disabled)
                # [Naming] Renamed _parts → ntds_fields to clarify what is being parsed.
                ntds_fields = line.strip().split(":")

                if len(ntds_fields) != 7:
                    print(
                        f"{Bcolors.FAIL}[-]{Bcolors.ENDC} Skipping malformed dump line: {line.strip()}"
                    )
                    continue

                username, _, _, nthash, _, _, status = ntds_fields

                if nthash in cracked_hashes:
                    password = cracked_hashes[nthash]
                    matches_found += 1

                    if "Enabled" in status:
                        # [Fix] Renamed _formated → formatted_username (typo fix).
                        formatted_username = self.format_username(username)
                        pass_file.write(f"{formatted_username}:{password}\n")
                        enabled_users += 1
                        print(
                            f"{Bcolors.OKGREEN}[+]{Bcolors.ENDC} Match found: "
                            f"{Bcolors.OKCYAN}{formatted_username}{Bcolors.ENDC}:"
                            f"{Bcolors.WARNING}{password}{Bcolors.ENDC}"
                        )

        return matches_found, enabled_users
