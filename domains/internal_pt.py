class InternalPT:
    """class will be responsible for handling all Internal PT"""

    def __init__(self, os_command, color, filemanager) -> None:
        self.output_file = "sample.txt"
        self.mode = "SCAN"
        self.run_os_command = os_command
        self.colors = color
        self.filemanager = filemanager

    def initialize_variables(self, mode, output_file):
        # Sets user provided values
        self.mode = mode
        self.output_file = output_file

    def resume_network_scan(self, scan_file):
        # read the last line of file and use it as start IP
        # scan_file is passed as an argument
        pass

    def save_live_hosts_to_host(self, hosts):
        """Save Live Hosts to file"""
        for host in hosts:
            self.filemanager.save_new_file(self.output_file, host)


    def resume_scan_from_file(self, file):
        """Resumes scan from file with previously stored IPs"""
        pass
