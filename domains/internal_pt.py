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

    def enumerate_hosts(self):
        """Enumerates all possible hosts on a network using ICMP protocol
        In order to increase your attack surface
        """
        self.network.get_live_ips(mode=self.mode, output=self.output_file)
        print(
            f"[+] {self.bcolors.BOLD}Your File is located at:{self.bcolors.ENDC}{self.bcolors.BOLD}{self.bcolors.OKGREEN}{self.output_file}{self.bcolors.ENDC}"
        )

    # Using CrackmapExec / Netexec Module
    ## 1. enum shares
    ## 2. enum users
    ## 3. Pass policy
    ## 4. Dumps
    ## 5. SMB relay

    # BloodHound
