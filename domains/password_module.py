from handlers import DisplayHandler
from utils.internal.hash_util import HashUtil


class PasswordModule(DisplayHandler, HashUtil):
    """Class that handles password operations """

    def __init__(self):
        super().__init__()
        self.cracked_hashes = None
        self.dumped_hashes = None
        self.output_file = ""

    def set_domain_variables(self, domain_variables, save_dir, generate_filename):
        """Initialize class attributes"""
        filename = generate_filename(domain_variables['filename'])
        self.cracked_hashes = domain_variables["cracked_hashes"]
        self.dumped_hashes = domain_variables["dumps"]
        self.output_file = f"{save_dir}/{filename}"

    def generate_passlist_from_hashes(self):
        """Generate user:pass list from cracked hashes and ntds dump"""
        matches_found, enabled_accounts = self.compare_hash_from_dump(
            self.cracked_hashes,
            self.dumped_hashes,
            self.output_file
        )
        self.print_success_message(
            f"[*] Found {matches_found} password matches, and written {enabled_accounts} "
            "Enabled users to ", extras=self.output_file)
