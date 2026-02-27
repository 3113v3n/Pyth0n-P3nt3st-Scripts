from handlers import DisplayHandler
from utils.internal.hash_util import HashUtil
from utils.internal.test_creds import CredentialsUtil


class PasswordModule(DisplayHandler, HashUtil, CredentialsUtil):
    """Class that handles password operations """

    def __init__(self):
        super().__init__()
        self.cracked_hashes = None
        self.dumped_hashes = None
        self.output_file = ""
        self.output_dir = ""
        self.pass_list = ""
        # [AI] Set by PentestFramework.initialize_classes(); None means disabled
        self.ai = None

    def generate_password_list_from_hashes(
            self,
            domain_variables: dict,
            save_dir: str,
            generate_filename: callable):
        """Generate user:pass list from cracked hashes and ntds dump
        :param domain_variables: dictionary containing domain-specific variables
        :param save_dir: directory to save the output files
        :param generate_filename: function that generates a unique output file name
        """
        if domain_variables["hashes"]:
            print("Getting cracked hashes")
            self.cracked_hashes = domain_variables["hashes"]
            self.dumped_hashes = domain_variables["dumps"]
        filename = generate_filename(domain_variables['filename'])
        self.output_file = f"{save_dir}/{filename}"
        matches_found, enabled_accounts = self.compare_hash_from_dump(
            self.cracked_hashes,
            self.dumped_hashes,
            self.output_file
        )
        self.print_success_message(
            f"[*] Found {matches_found} password matches, and written {enabled_accounts} "
            "Enabled users to ", extras=self.output_file)

        # [AI] Analyse recovered passwords for policy weakness patterns.
        # Passwords are read from the output file so we never keep them in memory.
        if self.ai and self.ai.enabled and matches_found > 0:
            password_list = self._read_passwords_from_output()
            if password_list:
                ai_analysis = self.ai.analyze_password_patterns(password_list)
                self.print_success_message(
                    message="AI Password Policy Analysis:", extras=f"\n{ai_analysis}")

    def _read_passwords_from_output(self) -> list[str]:
        """Read plaintext passwords written to the output file.

        The output file has lines formatted as ``user:password``.  Only the
        password portion is extracted to keep the list tidy for AI analysis.

        Returns:
            List of plaintext password strings (empty on error / missing file).
        """
        passwords: list[str] = []
        if not self.output_file:
            return passwords
        try:
            with open(self.output_file, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if ":" in line:
                        # format is  user:password  (ignore account-disabled markers)
                        passwords.append(line.split(":", 1)[1])
        except OSError:
            pass
        return passwords

    def test_valid_passwords(
            self,
            domain_variables: dict,
            generate_filename: callable,
            save_dir: str,
    ):
        """
        Test credentials against particular host
        :param domain_variables: dictionary containing domain-specific variables
        :param save_dir: directory to save the output files
        :param generate_filename: function that generates a unique output file name
        """

        filename = generate_filename(domain_variables['filename'])
        self.pass_list = domain_variables["pass_file"]
        self.output_file = f"{save_dir}/{filename}"
        domain = domain_variables["domain"]
        target = domain_variables["target"]

        self.test_credentials(
            target,
            domain,
            self.output_file,
            self.pass_list,
            save_dir)
