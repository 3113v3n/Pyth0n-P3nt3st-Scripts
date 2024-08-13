from handlers import FileHandler, NetworkHandler
from utils import bcolors, NetExec


class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(
        self,
        filemanager: FileHandler,
        network: NetworkHandler,
        colors: bcolors,
        netexec: NetExec,
    ) -> None:
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.filemanager = filemanager
        self.bcolors = colors
        self.network = network
        self.nc = netexec

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        if mode == "scan":
            self.output_file = self.filemanager.generate_unique_name(output_file, "csv")
        else:
            self.output_file = output_file

    def enumerate_hosts(self):
        """Enumerates all possible hosts on a network using ICMP protocol
        In order to increase your attack surface
        """
        self.network.get_live_ips(mode=self.mode, output=self.output_file)
        print(
            f"[+] {self.bcolors.BOLD}Your File is located at:{self.bcolors.ENDC}{self.bcolors.BOLD}{self.bcolors.OKGREEN}{self.filemanager.full_file_path}{self.bcolors.ENDC}"
        )

    def netexec_module(self):
        # Using CrackmapExec / Netexec Module
        ## 1. enum shares
        ## 2. enum users
        ## 3. Pass policy
        ## 4. Dumps
        ## 5. SMB relay
        def gen_smb_list(input, output):
            return self.nc.gen_relay_list(input, output)

        ## 6. Compare Hashes
        return {"relay-list": self.gen_smb_list}

    # BloodHound
    # secrets dump
