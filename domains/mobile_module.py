from utils.mobile import MobileCommands


class MobileAssessment(MobileCommands):
    # class will be responsible for all mobile operations
    def __init__(self) -> None:
        super().__init__()  # commands: MobileCommands
        self.package_name = ""
        self.package_path = ""

    @classmethod
    def reset_class_states(cls):
        """Reset the states of the class"""
        cls.package_name = ""
        cls.package_path = ""

    def initialize_variables(self, data):
        # Sets user provided values
        self.package_name = data["filename"]  # application filename
        self.package_path = data["full_path"]  # fullpath to the application

    def _inspect_files(self, test_domain):
        try:

            self.inspect_application_files(
                application=self.package_path, test_domain=test_domain
            )
            self.print_total_time(f"Total analysis time for {self.package_name}")
        finally:
            pass
            self.reset_total_time()

    # Install web proxies cert
    # 1. Take filepath to .der

    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
