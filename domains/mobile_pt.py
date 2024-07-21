class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(self, os_commands,colors) -> None:
        self.package_name = ""
        self.command = os_commands
        self.colors = colors
    
    def initialize_variables(self,data):
        # Sets user provided values
        self.package_name = data["package_name"]

    def find_package_in_device(self):
        self.command.run_os_commands(
            f"adb shell cmd package list packages | grep ${self.package_name}"
        )
