from utils.shared import Config


class HelpHandler(Config):
    def __init__(self):
        super().__init__()
        pass
    def internal_helper(self, submodule: str) -> str:
        """Print helper function
        :param submodule: one of scanner | hashfunction
                scanner: shows help function for internal PT
                hashfunction: shows help function when handling hashes
        """
        module = {
            "scanner": self.SCANNER_HELPER_STRING,
            "hashfunction": self.HASH_HELPER_STRING
        }
        text_ = module[submodule]
        print(text_)
