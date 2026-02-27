from handlers import NetworkHandler, DisplayHandler, HelpHandler


# NetExec

class InternalAssessment(DisplayHandler):
    """class will be responsible for handling all Internal PT"""

    def __init__(self, network: NetworkHandler, helper_instance: HelpHandler) -> None:
        super().__init__()
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.network_manager = network
        self._helper = helper_instance
        self.hide_helper = False
        # [AI] Set by PentestFramework.initialize_classes(); None means disabled
        self.ai = None

    @classmethod
    def reset_class_states(cls, network: NetworkHandler):
        """Reset the states of the class"""
        cls.output_file = "sample.txt"
        cls.mode = "SCAN"
        cls.network_manager = network

    def initialize_variables(self, mode, output_file, is_cmdl=False):
        # Sets user provided values

        self.mode = mode
        self.hide_helper = is_cmdl
        if mode == "scan":
            self.output_file = self.network_manager.generate_unique_name(
                output_file, "csv")
        else:

            self.output_file = output_file

    def enumerate_hosts(self):
        """Lists all possible hosts on a network using ICMP protocol
         to increase your attack surface
        """
        if not self.hide_helper:
            #self._helper.internal_helper("scanner")
            pass
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

            # [AI] Suggest likely host roles for discovered IPs.
            if self.ai and self.ai.enabled:
                live_ips = self._read_live_ips(live)
                if live_ips:
                    ai_analysis = self.ai.suggest_host_roles(live_ips)
                    self.print_success_message(
                        message="AI Host Role Suggestions:", extras=f"\n{ai_analysis}")

        # Delete unresponsive file only if scan completed successfully
        if self.network_manager.scan_complete and unresponsive:
            self.network_manager.remove_file(unresponsive)
            self.print_success_message(
                "Scan completed, removed unresponsive file: ")
        elif unresponsive:
            self.print_warning_message(
                "Scan incomplete, retaining unresponsive file ", file_path=unresponsive)

    @staticmethod
    def _read_live_ips(filepath: str) -> list[str]:
        """Read live IP addresses from the output CSV written by the network scan.

        Args:
            filepath: Path to the CSV file containing live hosts.

        Returns:
            List of IP address strings, or empty list on error.
        """
        ips: list[str] = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # CSV may have additional columns; first column is the IP
                        ips.append(line.split(",")[0])
        except OSError:
            pass
        return ips

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
