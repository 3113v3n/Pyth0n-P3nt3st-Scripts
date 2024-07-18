class ExternalPT:
    """Class will be responsible for handling external PT operations"""

    def __init__(self, os_command, color) -> None:
        self.target_domain = ""
        self.command = os_command
        self.color = color

    def initialize_variables(self, variables):
        self.target_domain = variables["target_domain"]
