from handlers.file_handler import FileHandler
from handlers.network_handler import NetworkHandler
from utils.colors import bcolors


class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(
        self, filemanager: FileHandler, network: NetworkHandler, colors: bcolors
    ) -> None:
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.filemanager = filemanager
        self.bcolors = colors
        self.network = network

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        if mode == "scan":
            self.output_file = self.filemanager.generate_unique_name(output_file)
        else:
            self.output_file = output_file

    def save_live_hosts_to_host(self, hosts):
        """Save Live Hosts to file"""
        if len(hosts) != 0:
            for host in hosts:
                self.filemanager.save_new_file(self.output_file, host)
            print(
                f"[+] File Location:\n{self.bcolors.OKGREEN}{self.filemanager.full_file_path}{self.bcolors.ENDC}"
            )

    def resume_scan_from_file(self):
        """Resumes scan from file with previously stored IPs"""
        print(f"\n{self.mode}\n{self.output_file}")
