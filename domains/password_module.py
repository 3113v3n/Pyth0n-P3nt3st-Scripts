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

    def generate_passlist_from_hashes(
            self,
            domain_variables: dict,
            save_dir: str,
            generate_filename: callable):
        """Generate user:pass list from cracked hashes and ntds dump"""
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

    def test_valid_passwords(
            self,
            domain_variables: dict,
            generate_filename: callable,
            save_dir: str,
    ):
        """
        Test credentials against hosts
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
