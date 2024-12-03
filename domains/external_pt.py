from utils.shared import bcolors, Commands


class ExternalAssessment:
    """Class will be responsible for handling external PT operations"""

    def __init__(self) -> None:
        self.target_domain = ""
        self.command = Commands()
        self.color = bcolors

    def initialize_variables(self, variables):
        # set user provided variables
        self.target_domain = variables["target_domain"]

    def bbot_enum(self, output_dir):
        self.command.auto_enter_commands(
            f"bbot -t {self.target_domain} -f subdomain-enum email-enum cloud-enum web-basic -m nmap gowitness nuclei --allow-deadly -o {output_dir}"
        )
