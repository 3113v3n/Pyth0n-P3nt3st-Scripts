from curses import wrapper
import time
from tqdm import tqdm
from utils.progress_bar import ProgressBar
from utils.commands import Commands


class NetworkHandler:
    """Class will handle any logic necessary for network operations"""

    def __init__(self, filemanager) -> None:
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
        self.os_commands = Commands()
        self.progress_bar = ""
        self.filemanager = filemanager

    def initialize_network_variables(self, variables):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        network_info = get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.progress_bar = ProgressBar(self.hosts)

    def get_live_ips(self, mode, output) -> list:
        wrapper(self.show_progress, mode, output)
        return self.progress_bar.live_hosts

    def show_progress(self, stdscr, mode, output):

        octets = self.user_ip_addr.split(".")
        if mode == "scan":
            self.scan_network(
                stdscr=stdscr,
                octets=octets,
                x_range=256,
                y_range=256,
                z_range=256,
                output_file=output,
            )
        else:
            # increment the scan start ip by 1 depending on the selected network range
            x_plus_1 = int(octets[3]) + 1
            y_plus_1 = int(octets[2]) + 1
            z_plus_1 = int(octets[1]) + 1
            self.scan_network(
                stdscr=stdscr,
                octets=octets,
                x_range=(x_plus_1, 256),
                y_range=(y_plus_1, 256),
                z_range=(z_plus_1, 256),
                output_file=output,
            )

    def scan_network(self, stdscr, octets, x_range, y_range, z_range, output_file):
        """
        Splits the user provided IP into 4 octets and determines
        which octet to iterate over depending on the remaining subnet bits
        and returns a list of hosts that respond successfully to ping command

        Example:
        /16
        host_bits = 32 -18
            = 14
            xxxxxxxx.xxxxxxxx.yyyyyyyy.yyyyyyyy
            scanning octet = octet[2] and octet[3]
        """
        # Host bits
        if self.host_bits <= 8:
            # Example: 192.168.10.X
            base_ip = f"{octets[0]}.{octets[1]}.{octets[2]}"
            for x in tqdm(range(x_range), desc="Scanning Network", leave=False):
                self.configure_progress_bar(
                    stdscr=stdscr, output_file=output_file, ip=f"{base_ip}.{x}"
                )
        # Host bits > 8 and <= 16
        elif 16 >= self.host_bits > 8:
            # Example: 192.168.X.X
            base_ip = f"{octets[0]}.{octets[1]}"
            for x in tqdm(range(x_range), desc="Scanning Network", leave=False):
                for y in range(z_range):
                    self.configure_progress_bar(
                        stdscr=stdscr, output_file=output_file, ip=f"{base_ip}.{x}.{y}"
                    )

        # Host bits > 16 and <= 24
        elif 24 >= self.host_bits > 16:
            # Example: 192.X.X.X
            base_ip = f"{octets[0]}"
            for x in tqdm(range(x_range), desc="Scanning Network", leave=False):
                for y in range(z_range):
                    for z in range(y_range):
                        self.configure_progress_bar(
                            stdscr=stdscr,
                            output_file=output_file,
                            ip=f"{base_ip}.{x}.{y}.{z}",
                        )

    def configure_progress_bar(self, stdscr, ip, output_file):
        is_alive = self.os_commands.ping_hosts(ip)
        self.progress_bar.update_ips(
            self.filemanager,
            output_file=output_file,
            stdscr=stdscr,
            ip=ip,
            is_alive=is_alive,
        )
        time.sleep(0.01)


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
        "hosts": (2**bits),  # - 2
        "network_mask": int(network_mask),
        "host_bits": bits,
    }
    return ip_info
