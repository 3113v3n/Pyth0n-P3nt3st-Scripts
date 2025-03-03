from handlers import NetworkHandler, DisplayHandler


# NetExec

class InternalAssessment(DisplayHandler):
    """class will be responsible for handling all Internal PT"""

    def __init__(self, network: NetworkHandler) -> None:
        super().__init__()
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.network_manager = network

    @classmethod
    def reset_class_states(cls, network: NetworkHandler):
        """Reset the states of the class"""
        cls.output_file = "sample.txt"
        cls.mode = "SCAN"
        cls.network_manager = network

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        if mode == "scan":
            self.output_file = self.network_manager.generate_unique_name(
                output_file, "csv")
        else:

            self.output_file = output_file

    def enumerate_hosts(self):
        """Lists all possible hosts on a network using ICMP protocol
         to increase your attack surface
        """
        live_ip_count = self.network_manager.get_live_ips(
            output=self.output_file)
        paths = self.network_manager.get_file_paths()
        live = f"{paths['live_hosts']}"
        unresponsive = f"{paths['unresponsive_hosts']}"

        if live_ip_count > 0:
            self.print_success_message(
                message=f"Discovered {live_ip_count} hosts, and saved them to: ",
                extras=live
            )
        # Delete unresponsive file only if scan completed successfully
        if self.network_manager.scan_complete and unresponsive:
            self.network_manager.remove_file(unresponsive)
            self.print_success_message(
                "Scan completed, removed unresponsive file: ")
        elif unresponsive:
            self.print_warning_message(
                "Scan incomplete, retaining unresponsive file ", file_path=unresponsive)
       

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
