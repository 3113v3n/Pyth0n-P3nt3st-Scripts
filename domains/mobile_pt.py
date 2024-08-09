from utils.colors import bcolors
from utils.commands import Commands


class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(self) -> None:
        self.package_name = ""
        self.command = Commands()
        self.colors = bcolors

    def initialize_variables(self, data):
        # Sets user provided values
        self.package_name = data["package_name"]

    def find_package_in_device(self):
        self.command.run_os_commands(
            f"adb shell cmd package list packages | grep ${self.package_name}"
        )
    
    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
