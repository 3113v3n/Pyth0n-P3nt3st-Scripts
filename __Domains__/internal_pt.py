class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(self, os_command) -> None:
        self.subnet = ""
        self.output_file = ""
        self.mode = "SCAN"
        self.run_os_command = os_command
        self.hosts = 0

    def initialize_variables(self, variables):
        self.subnet = variables["subnet"]
        self.mode = variables["mode"]
        self.output_file = variables["output"]
        self.hosts = determine_num_hosts(self.subnet)

    def resume_network_scan(self, scan_file):
        # read the last line of file and use it as start IP
        # scan_file is passed as an argument
        pass

    def ping_hosts(self, ips):
        pass

    def scan_diff_subnets(self, subnet):
        pass

    def resume_scan_from_file(self, file):
        """Resumes scan from file with previously stored IPs"""
        pass


def determine_num_hosts(subnet):
    # determine num of hosts from IP addr
    # 2^(remaining bits)-2 = usable_hosts
    cidr = subnet.split("/")[1]
    bits = 32 - int(cidr)
    return (2 ** bits) - 2
