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
        """Determine which hosts are alive within the network"""
        alive_hosts = []
        for host in hosts:
            response = self.run_os_command.ping_hosts(host)
            if response:
                # add hosts to list if ping is successful
                # TODO: write these hosts to a file
                print(
                    f"{self.colors.OKGREEN}{self.colors.BOLD}[+] {host}{self.colors.ENDC}"
                )
                self.filemanager.save_new_file(self.output_file, host)
                alive_hosts.append(host)
            else:
                print(
                    f"{self.colors.FAIL}{self.colors.BOLD}[-] {host}{self.colors.ENDC}"
                )
            # TODO: display to the user scan progress
            # print(f"Scanned {self.total_scanned_ips} / {self.hosts}")
        return alive_hosts

    def resume_scan_from_file(self, file):
        """Resumes scan from file with previously stored IPs"""
        pass
