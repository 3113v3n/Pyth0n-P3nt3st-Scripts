from handlers import FileHandler
from utils.mobile import MobileCommands
from utils.shared import Commands, bcolors


class MobilePT:
    # class will be responsible for all mobile operations
    def __init__(
        self, MobileCommands: MobileCommands, filemanager: FileHandler
    ) -> None:
        self.package_name = ""
        self.package_path = ""
        self.mobile_cmds = MobileCommands
        self.command = Commands()
        self.colors = bcolors
        self.filemanager = filemanager
        self.output_dir = ""
        self.output_name = ""

    def initialize_variables(self, data):
        # Sets user provided values
        self.package_name = data["filename"]
        self.package_path = data["full_path"]

    def inspect_application_files(self):
        folder_name = ""
        if self.mobile_cmds.folder_name == "":
            folder_name = self.mobile_cmds.decompile_application(self.package_path)
        # filename = self.mobile_cmds.file_name
        # self.output_dir = self.filemanager.output_directory
        # self.output_name = f"{self.output_dir}/{filename}"

        # self.mobile_cmds.find_files(folder_name, "Sample")  # ios only

        self.mobile_cmds.find_hardcoded_data(
            folder_name, f"{self.output_name}_hardcoded.txt"
        )
        # self.mobile_cmds.get_base64_strings(self.output_dir, self.output_name)

    # Install web proxies cert
    ## Take filepath to .der

    """ Bypass permission denied
    adb shell su -c 'cat ~/somefile.txt' > somefile.txt

    adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
    """
