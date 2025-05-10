import curses
import signal
import threading
import netifaces
import sys
import time
# import psutil
import ipaddress
import os
from tqdm import tqdm
from typing import Iterator, List
from concurrent.futures import ThreadPoolExecutor, as_completed
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
        self.ip_alive = False
        self.mode = "scan"
        self.network_base_int = 0
        # Shell commands
        self.progress_bar = None
        self.live_ip_count = 0
        self.scan_complete = False
        # Handle Interfaces
        self.scan_thread = None
        self.monitor_thread = None
        self.interface = None
        self.is_interface_active = False
        self.initial_interface_ip = None
        self.debug = False
        self.lock = threading.Lock()  # prevent race conditions
        self.shutdown_event = threading.Event()

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
        cls.scan_thread = None
        cls.interface = None
        cls.is_interface_active = False
        cls.lock = threading.Lock()
        cls.shutdown_event = threading.Event()
        cls.scan_complete = False

    def initialize_network_variables(self, variables, test_domain, progress_bar):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        self.interface = variables["interface"]
        network_info = self.get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.mode = variables["action"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.network_base_int = network_info["network_base_int"]
        self.progress_bar = progress_bar()
        self.update_output_directory(test_domain)
        self.initial_interface_ip = self.get_interface_ip(self.interface)

    @staticmethod
    def get_interface_ip(interface: str) -> str | None:
        """Get the IPv4 address of the specified interface."""
        try:
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                for addr in addresses[netifaces.AF_INET]:
                    ip = addr.get('addr')
                    if ip and ip != '127.0.0.1' and not ip.startswith("169."):
                        return ip
            return None
        except (ValueError, KeyError):
            return None

    def port_discovery(self):
        # use masscan to discover open ports incase ICMP is disabled
        # Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
        # masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
        pass

    def generate_filename(self, mode: str, is_alive: bool, filename: str) -> str:
        """
        Generate a filename based on mode and host responsiveness.

        :param mode: Operation mode ('scan' or 'resume')
        :param is_alive: True if the host responsiveness
        :param filename: Base filename to modify
        :return: Formatted filename
        """
        basename = self.get_filename_without_extension(filename)
        extension = ".csv"
        suffix = "_unresponsive_hosts"

        if is_alive:
            if mode == "resume":
                return filename.replace(suffix, "")
            return filename

        if suffix not in basename:
            return f"{basename}{suffix}{extension}"
        return f"{basename}{extension}"

    def scan_network(self, stdscr, mode, output_file):

        stdscr.clear()
        stdscr.addstr(0, 0, "Network Scanner - Press Ctrl+C to stop")
        stdscr.refresh()
        curses.curs_set(0)
        curses.echo(False)
        if self.debug:
            print(
                f"DEBUG: scan_network started with mode={mode}, output_file={output_file}")
        # Interface check before scanning
        if not self.interface:
            self.interface = self.get_active_interface()
            if self.debug:
                print(f"DEBUG: Auto-detected interface={self.interface}")
            if not self.interface:
                stdscr.addstr(4, 0, "No active interface found.")
                stdscr.refresh()
                curses.napms(1000)
                return
        current_ip = self.get_interface_ip(self.interface)
        if self.debug:
            print(f"DEBUG: Current IP for {self.interface}={current_ip}")
        if not current_ip:
            stdscr.addstr(4, 0, f"Interface {self.interface} has no valid IP.")
            stdscr.refresh()
            curses.napms(1000)
            return
        self.initial_interface_ip = current_ip  # Set for monitoring

        # Signal handler for SIGINT (Ctrl+C)
        def signal_handler(sig, frame):
            self.shutdown_event.set()
            stdscr.addstr(4, 0, "Shutting down...")
            stdscr.refresh()
            curses.napms(500)

        signal.signal(signal.SIGINT, signal_handler)

        executor = None
        try:
            self.mode = mode
            remaining_hosts = self.calculate_remaining_hosts(
                self.user_ip_addr) if self.mode == "resume" else self.hosts
            if self.debug:
                print(f"DEBUG: Total hosts to scan={remaining_hosts}")

            max_workers = min(50, os.cpu_count() * 2)
            processed = 0
            total = remaining_hosts
            batches = list(self.generate_ip_in_batches())
            if self.debug:
                print(f"DEBUG: Generated {len(batches)} IP batches")

            # Start interface monitoring thread
            self.monitor_thread = threading.Thread(
                target=self.monitor_interface, args=(stdscr,))
            self.monitor_thread.start()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                with tqdm(total=total, desc="Scanning", file=sys.stdout, leave=False) as pbar:
                    for ip_batch in batches:
                        if self.shutdown_event.is_set():
                            if self.debug:
                                print("DEBUG: Scan stopped by shutdown event")
                            break
                        if self.debug:
                            print(
                                f"DEBUG: Processing batch of {len(ip_batch)} IPs")
                        futures = {executor.submit(
                            self.set_progressbar, mode, output_file, ip, stdscr):
                                       ip for ip in ip_batch}
                        for _ in as_completed(futures):
                            if self.shutdown_event.is_set():
                                break
                            processed += 1
                            if processed % 100 == 0 or processed == total:  # Update UI every 100 IPs
                                pbar.update(100)
                        pbar.update(100)
            # set scan complete when done
            self.scan_complete = not self.shutdown_event.is_set()
            if self.debug:
                print(f"DEBUG: Scan completed={self.scan_complete}")
        except Exception as e:
            stdscr.addstr(4, 0, f"Error: {e}")
            stdscr.refresh()
            curses.napms(1000)
            self.scan_complete = False
            if self.debug:
                print(f"DEBUG: Scan failed with error={e}")
        finally:
            print("Final cleanup...")
            self.shutdown_event.set()  # Ensure monitor thread stops
            if self.monitor_thread:
                self.monitor_thread.join()
            if executor:
                executor.shutdown(wait=False)

    def get_live_ips(self, output: str) -> int:
        """Enumerates all IPs in a given network using ICMP ping command
        :param mode: mode to use (SCAN | RESUME)
               output: Name of the output file
        :return number of ips that are alive
        """
        try:
            if self.debug:
                print(
                    f"DEBUG: get_live_ips called with output={output}, mode={self.mode}, subnet={self.subnet}, interface={self.interface}")
            # Initialize the progress bar
            curses.wrapper(self.scan_network, self.mode, output)
            # self.print_debug_message(f"Last unresponsive IP:  {self.user_ip_addr}")
            if self.debug:
                print("DEBUG: curses.wrapper completed, "
                      f"live hosts={len(self.progress_bar.live_hosts) if self.progress_bar else 0}")
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
            self.scan_complete = False  # Scan interrupted
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except Exception as e:
            if self.debug:
                print(f"DEBUG: curses.wrapper failed with {e}")
            self.print_error_message(exception_error=e)
            self.scan_complete = False  # Scan exception
            return 0

    def generate_ip_in_batches(self, batch_size: int = 2000):
        """Generates IP ranges in batches"""
        network = ipaddress.ip_network(
            self.subnet, strict=False)  # subnet = 10.10.2.3/24
        self.hosts = self.calculate_remaining_hosts(
            self.user_ip_addr) if self.mode == "resume" else self.hosts
        # update the total host values in progress bar
        self.progress_bar.set_total_hosts(self.hosts)
        start_ip = ipaddress.ip_address(
            self.user_ip_addr) if self.mode == "resume" else network.network_address

        def chunked_ips() -> Iterator[List[str]]:
            ip_list = []
            # Iterate over IPs from start_ip to the end of network
            current_ip = start_ip
            for ip_int in range(int(current_ip), int(network.broadcast_address) + 1):
                ip = ipaddress.ip_address(ip_int)
                if ip in network:
                    ip_str = str(ip)
                    ip_list.append(ip_str)
                    if len(ip_list) >= batch_size:
                        yield ip_list
                        ip_list = []
            if ip_list:  # Yield any remaining IPs
                yield ip_list

        return chunked_ips()

    def set_progressbar(self, mode, filename, ip, stdscr):
        """Check if the host is alive using asynchronous pings and update UI"""
        if self.shutdown_event.is_set():
            return
        try:
            is_alive = self.start_async_ping(ip)  # self.ping_hosts(ip)
            with self.lock:  # Prevents concurrent writes
                self.progress_bar.update_ips(
                    filename, mode, ip, is_alive, stdscr,
                    self.save_to_csv, self.generate_filename, self.existing_unresponsive_ips)
                # Update live IP count on screen
                self.live_ip_count = len(self.progress_bar.live_hosts)
                stdscr.refresh()
        except Exception as error:
            self.print_error_message(
                f"set Progress bar failed for IP: {ip} : ", exception_error=error)

    @staticmethod
    def get_network_info(subnet) -> dict:
        """
        Function takes in network subnet and splits the provided
        Values into an ip address and subnet.
        It then returns a dictionary containing
        """
        # determine num of hosts from IP addr
        # 2^(remaining bits)-2 = usable_hosts
        ip, mask = subnet.split("/")
        mask = int(mask)
        bits = 32 - mask
        total_hosts = (2 ** bits)
        octets = list(map(int, ip.split(".")))
        network_mask_int = 0xFFFFFFFF << bits
        ip_int = (octets[0] << 24) + (octets[1] << 16) + \
                 (octets[2] << 8) + octets[3]
        network_base_int = ip_int & network_mask_int
        return {
            "ip_address": ip,
            "hosts": total_hosts,  # - 2
            "network_mask": mask,
            "host_bits": bits,
            "network_base_int": network_base_int
        }

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
                (W + X + Y + Z)

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
            start_ip_int = (octets[0] << 24) + (octets[1] << 16) \
                           + (octets[2] << 8) + octets[3]

            # Calculate last IP in subnet
            last_ip_int = self.network_base_int + total_hosts - 1
            # Calculate remaining hosts
            return last_ip_int - start_ip_int + 1

        except Exception as e:
            self.print_error_message(exception_error=e)

    # TODO: include interface check before scanning
    def _is_interface_active(self, interface: str) -> bool:
        """Check if the interface is active and unchanged."""
        current_ip = self.get_interface_ip(interface)
        if self.debug:
            print(
                f"DEBUG: Checking interface {interface}, current IP={current_ip}")
        if not current_ip:
            return False
        # Check if the IP has changed from the initial value
        if self.initial_interface_ip and current_ip != self.initial_interface_ip:
            return False
        return True

    def monitor_interface(self, stdscr):
        if self.debug:
            print(
                f"DEBUG: Monitoring interface {self.interface}, initial IP={self.initial_interface_ip}")
        while not self.shutdown_event.is_set():
            current_ip = self.get_interface_ip(self.interface)
            if self.debug:
                print(f"DEBUG: Current IP={current_ip}")
            if not current_ip or (self.initial_interface_ip and current_ip != self.initial_interface_ip):
                with self.lock:
                    if stdscr:
                        stdscr.addstr(
                            5, 0, f"Interface {self.interface} dropped or changed. Stopping scan.")
                        stdscr.refresh()
                    if self.debug:
                        print(
                            f"DEBUG: Interface {self.interface} changed or down, stopping scan")
                    self.shutdown_event.set()
                break
            time.sleep(1)

    def kill_scan(self):
        """Stop the network scan."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.shutdown_event.set()
            self.scan_thread.join()
            self.monitor_thread.join()
            print("Scan stopped.")


def get_active_interface():
    """"Getting the active interface
    Returns the default gateway and interface name
    """

    try:
        active_ = netifaces.gateways()
        default_gateway: tuple = active_[2][0]

        if default_gateway:
            interface_tuple = default_gateway
            return interface_tuple
        else:
            print("No active interface found.")
    except (KeyError, AttributeError, IndexError):
        pass


def get_network_interfaces() -> List[str]:
    """
    Get the network interfaces on the system
    """
    interfaces = netifaces.interfaces()
    return interfaces
