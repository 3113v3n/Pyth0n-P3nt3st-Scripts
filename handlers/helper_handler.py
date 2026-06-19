
from utils.shared import Config


class HelpHandler(Config):
    def __init__(self):
        super().__init__()

    def internal_helper(self, submodule: str) -> str:
        """Return helper text for internal scanner/password flows."""
        module = {
            "scanner": self.SCANNER_HELPER_STRING,
            "hashfunction": self.PASSWORD_HELPER_STRING,
        }
        return module[submodule]

    def external_helper(self) -> str:
        """Return helper text for External Penetration Testing."""
        return self.EXTERNAL_HELPER_STRING

    def vulnerability_helper(self) -> str:
        """Return helper text for Vulnerability Analysis."""
        return self.VULNERABILITY_HELPER_STRING

    def mobile_helper(self) -> str:
        """Return helper text for Mobile Penetration Testing."""
        return self.MOBILE_HELPER_STRING

    def main_program_helper(self) -> str:
        """Return helper text for the main program."""
        return self.PROGRAM_HELPER_STRING
