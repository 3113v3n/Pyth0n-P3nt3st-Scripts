from handlers import NetworkHandler
from utils.shared import Bcolors  # NetExec


class InternalAssessment(Bcolors):
    """class will be responsible for handling all Internal PT"""

    def __init__(self, network: NetworkHandler) -> None:
        super().__init__()
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.network_manager = network

    def initialize_variables(self,mode, output_file):
        # Sets user provided values
        self.mode = mode
        if mode == "scan":
            self.output_file = self.network_manager.generate_unique_name(output_file, "csv")
        else:

            self.output_file = output_file

    def enumerate_hosts(self):
        """Enumerates all possible hosts on a network using ICMP protocol
        In order to increase your attack surface
        """
        self.network_manager.get_live_ips(mode=self.mode, output=self.output_file)
        paths = self.network_manager.get_file_paths()
        live = f"{self.ENDC}{self.BOLD}{self.OKGREEN}{paths['live_hosts']}"
        unresponsive = f"{self.ENDC}{self.BOLD}{self.WARNING}{paths['unresponsive_hosts']}"

        print(
            f"\n{self.OKCYAN}[+] Your Live Hosts are located here: {live}{self.ENDC}\n"
            f"\n{self.HEADER}[!] Your Unresponsive Hosts are located here: {unresponsive}{self.ENDC}\n\n"
        )

    def netexec_module(self):
        # Using CrackmapExec / Netexec Module
        # 1. enum shares
        # 2. enum users
        # 3. Pass policy
        # 4. Dumps
        # 5. SMB relay
        # 6. Compare Hashes
        pass

    # BloodHound
    # secrets dump
