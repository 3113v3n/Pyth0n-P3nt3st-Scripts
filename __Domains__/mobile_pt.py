class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(self, os_commands, package_name) -> None:
        self.package_name = package_name
        self.command = os_commands

    def find_package_in_device(self):
        self.command.run_os_commands(
            f"adb shell cmd package list packages | grep ${self.package_name}"
        )
