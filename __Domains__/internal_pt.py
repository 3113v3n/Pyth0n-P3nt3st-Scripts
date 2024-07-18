class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(self, os_command) -> None:
        self.subnet = "0.0.0.0"
        self.output_file = ""
        self.mode = "SCAN"
        self.run_os_command = os_command

    def determine_num_hosts(self):
        # determine num of hosts from IP addr
        pass

    def resume_network_scan(self, scan_file):
        # read the last line of file and use it as start IP
        # scan_file is passed as an argument
        pass

    def ping_hosts(self, ips):
        pass

    def scan_diff_subnets(self, subnet):
        pass
