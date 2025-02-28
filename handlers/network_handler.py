import curses
import threading
import psutil
from tqdm import tqdm
import concurrent.futures
from handlers import FileHandler
# from scapy.all import IP, ICMP, sr1
from utils.shared import Commands


class NetworkHandler(FileHandler, Commands):
    """Class will handle any logic necessary for network operations"""

    def __init__(self) -> None:
        super().__init__()
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
        self.mode = "scan"
        # Shell commands
        self.progress_bar = None
        self.live_ip_count = 0
        self.lock = threading.Lock()  # prevent race conditions

    @classmethod
    def reset_class_states(cls):
        """Reset the states of the class"""
        cls.subnet = ""
        cls.hosts = 0
        cls.start_ip = ""
        cls.network_mask = ""
        cls.user_ip_addr = ""
        cls.host_bits = 0
        cls.mode = "scan"
        cls.progress_bar = None
        cls.lock = threading.Lock()

    def initialize_network_variables(self, variables, test_domain, progress_bar):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        network_info = self.get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.mode = variables["mode"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.progress_bar = progress_bar()
        self.update_output_directory(test_domain)

    def get_live_ips(self, output: str) -> int:
        """Enumerates all IPs in a given network using ICMP ping command
        :param mode: mode to use (SCAN | RESUME)
               output: Name of the output file
        :return number of ips that are alive
        """
        curses.wrapper(self.scan_network, self.mode, output)
        return len(self.progress_bar.live_hosts)

    def port_discovery(self):
        # use masscan to discover open ports incase ICMP is disabled
        # Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
        # masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
        pass

    def scan_network(self, stdscr, mode, output_file):
        # Check Memory
        self.print_info_message(
            f"Memory usage: {psutil.virtual_memory().percent}%")
        base_ip = self.user_ip_addr.split(".")
        ip_ranges = self.generate_ip_ranges(base_ip)
        self.mode = mode

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = {}
            for ip in ip_ranges:
                future = executor.submit(
                    self.set_progressbar, ip, output_file, mode, stdscr)
                futures[future] = ip
                while len(futures) >= 1000:
                    for future in concurrent.futures.as_completed(futures):
                        del futures[future]
                        break
            remaining_hosts = self.hosts - (
                int(base_ip[1]) * 256 * 256 +
                int(base_ip[2]) * 256 + int(base_ip[3])
            ) + 1 if mode == "resume" else self.hosts

            for _ in tqdm(
                concurrent.futures.as_completed(futures),
                total=remaining_hosts,
                desc="Scanning Network",
                leave=False,
            ):
                pass  # UI updates are handled inside scan_host()

    def generate_ip_ranges(self, base_ip) -> iter:
        """Generate IP addresses based on CIDR subnet provided """
        base_ip = list(map(int, base_ip))
        self.hosts = self.calculate_remaining_hosts(
            self.user_ip_addr
            ) if self.mode == "resume" else self.hosts
        
        #update the total host values in progress bar
        self.progress_bar.set_total_hosts(self.hosts)
        start_ip = self.user_ip_addr.split(
            ".") if self.mode == "resume" else None
        if start_ip:
            start_ip = list(map(int, start_ip))

        if self.host_bits <= 8:
            start_x = start_ip[3] if start_ip else 1
            for x in range(start_x, 256):
                yield f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{x}"
        elif 16 >= self.host_bits > 8:
            start_y = start_ip[2] if start_ip else 0
            start_x = start_ip[3] if start_ip else 0
            for y in range(start_y, 256):
                x_start = start_x if y == start_y and self.mode == "resume" else 0
                for x in range(x_start, 256):
                    yield f"{base_ip[0]}.{base_ip[1]}.{y}.{x}"
        elif 24 >= self.host_bits > 16:
            start_z = start_ip[1] if start_ip else 0
            start_y = start_ip[2] if start_ip else 0
            start_x = start_ip[3] if start_ip else 0
            for z in range(start_z, 256):
                y_start = start_y if z == start_z and self.mode == "resume" else 0
                for y in range(y_start, 256):
                    x_start = start_x if z == start_z and y == start_y and self.mode == "resume" else 0
                    for x in range(x_start, 256):
                        yield f"{base_ip[0]}.{z}.{y}.{x}"

    def set_progressbar(self, ip, output_file, mode, stdscr):
        """Check if the host is alive using concurrent pings and update UI"""
        try:
            is_alive = self.ping_hosts(ip)  # self.scapy_ping(ip)

            with self.lock:  # Prevents concurrent writes
                self.progress_bar.update_ips(
                    self.save_to_csv, output_file=output_file, stdscr=stdscr,
                    ip=ip,
                    is_alive=is_alive,
                    mode=mode,
                )
        except Exception as e:
            self.print_error_message(exception_error=e)
    # @staticmethod
    # def scapy_ping(ip) -> bool:
    #     """Sends an ICMP Echo Request using scapy and returns boolean value"""
    #     response = sr1(IP(dst=ip) / ICMP(), timeout=0.5, verbose=False)
    #     return response is not None

    @staticmethod
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

    def calculate_remaining_hosts(self, ip_string: str) -> int:
        """Converts IP to decimal equivalent
            w.x.y.z
            [STEPS]
            1. split IP into individual values [w, x, y, z]
            2. Multiply each octet by the corresponding power of 256

                w * 256³ = W
                x * 256² = X
                y * 256¹ = Y
                z * 256⁰ = Z

            3. Add the values together
                ( W + X + Y + Z )

        :param ip_string: IP address to convert
        :return decimal equivalent:
        """
        try:
            octets = [int(x) for x in ip_string.split(".")]  # [w, x, y, z]
            # result = 0
            # for i in range(1,3):
            #     result += (int(octets[i]) * (256 ** (3-i)))
            # return result
            total_hosts = self.hosts
            """
            octet[0] << 24
            example: 10 --> 00001010
                    <<  --> 00001010 00000000 00000000 00000000 ==> 167772160
            """
            start_ip_int = (octets[0] << 24) + (octets[1]
                                                << 16) + (octets[2] << 8) + octets[3]

            # Calculate network base address
            network_bits = 32 - self.network_mask
            network_mask = 0xFFFFFFFF << network_bits
            network_base = start_ip_int & network_mask

            # Calculate last IP in subnet
            last_ip_int = network_base + total_hosts - 1
            # Calculate remaining hosts
            remaining_hosts = last_ip_int - start_ip_int + 1
            return remaining_hosts
        except Exception as e:
            self.print_error_message(exception_error=e)
