class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(self, os_command) -> None:
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.run_os_command = os_command

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        self.output_file = output_file

    def resume_network_scan(self, scan_file):
        # read the last line of file and use it as start IP
        # scan_file is passed as an argument
        pass

    def ping_hosts(self, ips):
        pass

    def resume_scan_from_file(self, file):
        """Resumes scan from file with previously stored IPs"""
        pass
