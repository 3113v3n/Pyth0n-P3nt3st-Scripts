from handlers.file_handler import FileHandler
from utils.colors import bcolors


class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(self, filemanager: FileHandler, colors: bcolors) -> None:
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.filemanager = filemanager
        self.bcolors = colors

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        self.output_file = self.filemanager.generate_unique_name(output_file)

    def resume_network_scan(self, scan_file):
        # read the last line of file and use it as start IP
        # scan_file is passed as an argument
        pass

    def save_live_hosts_to_host(self, hosts):
        """Save Live Hosts to file"""
        if len(hosts) != 0:
            for host in hosts:
                self.filemanager.save_new_file(self.output_file, host)
            print(
                f"[+] File Location:\n{self.bcolors.OKGREEN}{self.filemanager.full_file_path}{self.bcolors.ENDC}"
            )

    def resume_scan_from_file(self, file):
        """Resumes scan from file with previously stored IPs"""
        pass
