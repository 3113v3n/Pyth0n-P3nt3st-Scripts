from utils.mobile import MobileCommands


class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(self, MobileCommands: MobileCommands) -> None:
        self.package_name = ""
        self.package_path = ""
        self.mobile_cmds = MobileCommands

    def initialize_variables(self, data):
        # Sets user provided values
        self.package_name = data["filename"]
        self.package_path = data["full_path"]

    def inspect_application_files(self):
        self.mobile_cmds.inspect_application_files(application=self.package_path)

    # Install web proxies cert
    ## Take filepath to .der

    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
