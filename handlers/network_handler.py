import curses
import concurrent.futures
import itertools
import threading
from tqdm import tqdm
from handlers import FileHandler


class NetworkHandler:
    """Class will handle any logic necessary for network operations"""

    def __init__(self, filemanager: FileHandler, commands) -> None:
        # subnet range
        self.subnet = ""
        # Number of hosts within the network
        self.hosts = 0
        # IP to start scan from
        self.start_ip = ""
        # CIDR value [0-32]
        self.network_mask = ""
        # user IP addr
        self.user_ip_addr = ""
        # remaining usable host bits
        self.host_bits = 0
        # Shell commands
        self.os_commands = commands()
        self.progress_bar = ""
        self.filemanager = filemanager
        self.lock = threading.Lock()  # prevent race conditions

    def initialize_network_variables(self, variables, progress_bar):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        network_info = get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.progress_bar = progress_bar(self.hosts)

    def get_live_ips(self, mode, output):
        curses.wrapper(self.scan_network, mode, output)
        return self.progress_bar.live_hosts

    def configure_progress_bar(self, stdscr, ip, output_file, mode):
        is_alive = self.os_commands.ping_hosts(ip)
        self.progress_bar.update_ips(
            self.filemanager,
            output_file=output_file,
            stdscr=stdscr,
            ip=ip,
            is_alive=is_alive,
            mode=mode,
        )

    def port_discovery(self):
        # use masscan to discover open ports incase ICMP is disabled
        # Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
        # masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
        pass

    def scan_network(self, stdscr, mode, output_file):
        base_ip = self.user_ip_addr.split(".")
        ip_ranges = self.generate_ip_ranges(base_ip)

        # Find the index of the start IP in the generated IP Ranges
        if mode == "resume":
            start_index = ip_ranges.index(self.user_ip_addr)
            ip_ranges = ip_ranges[start_index:]  # slice list to start from last unresponsive IP

        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = {
                executor.submit(self.scan_hosts, ip, output_file, mode, stdscr): ip
                for ip in ip_ranges
            }
            for _ in tqdm(
                    concurrent.futures.as_completed(futures),
                    total=len(ip_ranges),
                    desc="Scanning Network",
                    leave=False,
            ):
                pass  # UI updates are handled inside scan_host()

    def generate_ip_ranges(self, base_ip) -> list:
        """Generate IP addresses based on CIDR subnet provided"""
        base_ip = list(map(int, base_ip))  # ==> [192,168,0,1]

        if self.host_bits <= 8:
            return [
                f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{x}" for x in range(1, 256)
            ]
        elif 16 >= self.host_bits > 8:
            return [
                f"{base_ip[0]}.{base_ip[1]}.{y}.{x}"
                for y in range(256)
                for x in range(256)
            ]
        elif 24 >= self.host_bits > 16:
            return [
                f"{base_ip[0]}.{z}.{y}.{x}"
                for z, y, x in itertools.product(range(256), repeat=3)
            ]

    def scan_hosts(self, ip, output_file, mode, stdscr):
        """Check if host is alive using concurrent pings and update UI"""
        is_alive = self.os_commands.ping_hosts(ip)

        with self.lock:  # Prevents concurrent writes
            self.progress_bar.update_ips(
                self.filemanager,
                output_file=output_file,
                stdscr=stdscr,
                ip=ip,
                is_alive=is_alive,
                mode=mode,
            )


def get_network_info(subnet) -> dict:
    """
    Function takes in network subnet and splits the provided
    Values into an ip address and subnet.
    It then returns a dictionary containing
    """
    # determine num of hosts from IP addr
    # 2^(remaining bits)-2 = usable_hosts
    network_mask = subnet.split("/")[1]
    bits = 32 - int(network_mask)
    ip_info = {
        "ip_address": subnet.split("/")[0],
        "hosts": (2 ** bits),  # - 2
        "network_mask": int(network_mask),
        "host_bits": bits,
    }
    return ip_info
