from handlers import DisplayHandler
from utils.internal.hash_util import HashUtil
from utils.internal.password_output import build_password_output_path, read_passwords_from_output
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
        self.output_file = build_password_output_path(
            save_dir=save_dir,
            output_basename=domain_variables["filename"],
            name_generator=generate_filename,
        )

        password_list: list[str] = []
        if self.ai and self.ai.enabled:
            matches_found, enabled_accounts, password_list = self.compare_hash_from_dump_collect(
                self.cracked_hashes,
                self.dumped_hashes,
                self.output_file,
                emit_match_logs=False,
            )
        else:
            matches_found, enabled_accounts = self.compare_hash_from_dump(
                self.cracked_hashes,
                self.dumped_hashes,
                self.output_file,
                emit_match_logs=False,
            )

        self.print_success_message(
            f"[*] Found {matches_found} password matches, and written {enabled_accounts} "
            "Enabled users to ", extras=self.output_file)

        # [AI] Analyse recovered passwords for policy weakness patterns.
        if self.ai and self.ai.enabled and matches_found > 0:
            if not password_list:
                # Fallback path if collector returned nothing unexpectedly.
                password_list = read_passwords_from_output(self.output_file)
            if password_list:
                ai_analysis = self.ai.analyze_password_patterns(password_list)
                self.print_success_message(
                    message="AI Password Policy Analysis:", extras=f"\n{ai_analysis}")

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

        self.pass_list = domain_variables["pass_file"]
        self.output_file = build_password_output_path(
            save_dir=save_dir,
            output_basename=domain_variables["filename"],
            name_generator=generate_filename,
        )
        domain = domain_variables["domain"]
        target = domain_variables["target"]

        self.test_credentials(
            target,
            domain,
            self.output_file,
            self.pass_list,
            save_dir)
