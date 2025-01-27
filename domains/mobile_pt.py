from utils.mobile import MobileCommands


class MobileAssessment:
    # class will be responsible for all mobile operations
    def __init__(self, commands: MobileCommands) -> None:
        self.package_name = ""
        self.package_path = ""
        self.mobile_cmds = commands  # mobile specific commands

    def initialize_variables(self, data):
        # Sets user provided values
        self.package_name = data["filename"]  # application filename
        self.package_path = data["full_path"]  # fullpath to the application

    def inspect_application_files(self,test_domain):
        self.mobile_cmds.inspect_application_files(application=self.package_path,test_domain=test_domain)

    # Install web proxies cert
    # 1. Take filepath to .der

    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
