import curses
import signal
import threading
import sys
# import psutil
import os
from tqdm import tqdm
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
        cls.lock = threading.Lock()
        cls.shutdown_event = threading.Event()

    def initialize_network_variables(self, variables, test_domain, progress_bar):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        network_info = self.get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.mode = variables["mode"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.network_base_int = network_info["network_base_int"]
        self.progress_bar = progress_bar()
        self.update_output_directory(test_domain)

    def getliveips_curses(self, stdscr, output):
        """Wrapper to initialize curses and call scan_network"""
        # debug without curser
        # self.scan_network(None,self.mode,output)
        self.scan_network(self.mode, output)
        return len(self.progress_bar.live_hosts) if self.progress_bar else 0

    def port_discovery(self):
        # use masscan to discover open ports incase ICMP is disabled
        # Using masscan to scan top20ports of nmap in a /24 range (less than 5min)
        # masscan -p20,21-23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080 199.66.11.0/24
        pass

    def generate_filename(self, mode: str, is_alive: bool, filename: str) -> str:
        """
        Generate a filename based on mode and host responsiveness.

        :param mode: Operation mode ('scan' or 'resume')
        :param is_alive: Whether the host responded
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

    def scan_network(self, mode, output_file):
        if not self.curses_active or self.stdscr is None:
            raise RuntimeError("Curses not initialized properly")

        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Network Scanner - Press Ctrl+C to stop")
        self.stdscr.refresh()
        curses.curs_set(0)
        curses.echo(False)

        # Signal handler for SIGINT (Ctrl+C)
        def signal_handler(sig, frame):
            print("Signal received!")
            self.shutdown_event.set()
            self.stdscr.addstr(4, 0, "Shutting down...")
            self.stdscr.refresh()
            curses.napms(500)

        signal.signal(signal.SIGINT, signal_handler)

        executor = None
        try:
            base_ip = self.user_ip_addr.split(".")
            self.mode = mode
            remaining_hosts = self.calculate_remaining_hosts(
                self.user_ip_addr) if self.mode == "resume" else self.hosts

            max_workers = min(50, os.cpu_count() * 2)
            processed = 0
            total = remaining_hosts

            executor = ThreadPoolExecutor(max_workers=max_workers)
            with executor:
                batches = list(self.generate_ip_in_batches(base_ip))
                self.stdscr.addstr(2, 0, f"Scanning: {processed}/{total} (0%)")
                self.stdscr.refresh()

                for ip_batch in batches:
                    if self.shutdown_event.is_set():
                        break
                    futures = {
                        executor.submit(self.set_progressbar, mode, output_file, ip, self.stdscr): ip
                        for ip in ip_batch
                    }
                    for _ in as_completed(futures):
                        if self.shutdown_event.is_set():
                            break
                        processed += 1
                        if processed % 100 == 0 or processed == total:
                            percent = (processed / total) * 100
                            self.stdscr.addstr(
                                2, 0, f"Scanning: {processed}/{total} ({percent:.1f}%)")
                            self.stdscr.refresh()

        except Exception as e:
            self.stdscr.addstr(4, 0, f"Error: {e}")
            self.stdscr.refresh()
            curses.napms(1000)
        finally:
            print("Final cleanup...")
            if executor:
                executor.shutdown(wait=False)

        # Check Memory
        # self.print_info_message(
        #     f"Memory usage: {psutil.virtual_memory().percent}%")
        # try:
        #     base_ip = self.user_ip_addr.split(".")
        #     self.mode = mode
        #     remaining_hosts = self.calculate_remaining_hosts(
        #         self.user_ip_addr) if self.mode == "resume" else self.hosts

        #     # Dynamically adjust num of workers based on CPU cores
        #     max_workers = min(50, os.cpu_count() * 2)
        #     processed = 0

        #     with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # with tqdm(total=remaining_hosts, desc="Scanning Network", leave=False)as pbar:
                #     batches = list(self.generate_ip_in_batches(base_ip))
                #     for ip_batch in batches:
                #         futures = {executor.submit(
                #             self.set_progressbar, mode, output_file, ip, stdscr
                #         ): ip for ip in ip_batch}
                #         for _ in as_completed(futures):
                #             processed += 1
                #             if processed % 100 == 0 or processed == total:  # Update UI every 100 IPs
                #                 # self.save_ips(mode, filename=output_file)
                #                 pbar.update(100)
                #         pbar.update(processed % 100)

        # except KeyboardInterrupt:
        #     self.print_error_message("Scan interrupted by user")
        #     if stdscr is not None:
        #         curses.endwin() # reset terminal on interrupt
        #     raise
        # finally:
        #     # Gracefully reset terminal incase of any other exception
        #     if stdscr is not None:
        #         curses.endwin() # reset terminal on interrupt

        # Final flush
        # self.save_ips(mode, filename=output_file)

    def get_live_ips(self, output: str) -> int:
        """Enumerates all IPs in a given network using ICMP ping command
        :param mode: mode to use (SCAN | RESUME)
               output: Name of the output file
        :return number of ips that are alive
        """
        self.shutdown_event.clear()  # Reset shutdown flag
        self.stdscr = None
        try:
            self.stdscr = curses.initscr()
            if self.stdscr is None:
                raise RuntimeError("Failed to initialize curses")
            curses.curs_set(0)
            curses.echo(False)
            self.curses_active = True
            self.scan_network(self.mode, output)
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except Exception as e:
            if self.curses_active:
                self.stdscr.addstr(4, 0, f"Error: {e}")
                self.stdscr.refresh()
                curses.napms(1000)
            else:
                print(f"Error before curses: {e}")
            return 0
        finally:
            if self.curses_active and self.stdscr is not None:
                curses.echo()
                curses.curs_set(1)
                result = curses.endwin()
                self.curses_active = False
                self.stdscr = None

                self.print_debug_message(
                    f"Curses active: {self.curses_active}, stdscr: {self.stdscr}")
                if result == curses.ERR:
                    self.print_error_message(
                        "endwin() failed", exception_error=result)
                    sys.exit(1)
            if self.shutdown_event.is_set():
                sys.exit(0)

    # Override print_error_message to use curses
    def print_error_message(self, message, exception_error=None):
        if self.curses_active and self.stdscr is not None:
            self.stdscr.addstr(5, 0, f"{message}{exception_error}")
            self.stdscr.refresh()
        else:
            print(f"{message}{exception_error}")

    def save_ips(self, mode, filename):
        with self.lock:
            if self.progress_bar.live_hosts:
                self.save_to_csv(
                    filename,
                    list(self.progress_bar.live_hosts))
                # self.progress_bar.live_hosts.clear()
            else:
                self.save_to_csv(
                    filename,
                    list(self.progress_bar.unresponsive_hosts))
                # self.progress_bar.unresponsive_hosts.clear()

    def generate_ip_in_batches(self, base_ip, batch_size=2000):
        """Generates IP ranges in batches"""
        base_ip = list(map(int, base_ip))
        self.hosts = self.calculate_remaining_hosts(
            self.user_ip_addr) if self.mode == "resume" else self.hosts
        # update the total host values in progress bar
        self.progress_bar.set_total_hosts(self.hosts)
        start_ip = list(map(int, self.user_ip_addr.split("."))
                        ) if self.mode == "resume" else None

        def chunked_ips():
            ip_list = []
            if self.host_bits <= 8:
                # 10.2.3.X
                start_x = start_ip[3] if start_ip else 0
                for x in range(start_x, 256):
                    ip_list.append(
                        f"{base_ip[0]}.{base_ip[1]}.{base_ip[2]}.{x}")
                    if len(ip_list) >= batch_size:
                        yield ip_list
                        ip_list = []
                if ip_list:
                    yield ip_list

            elif 16 >= self.host_bits > 8:
                # 10.2.Y.X
                start_x = start_ip[3] if start_ip else 0
                start_y = start_ip[2] if start_ip else 0
                for y in range(start_y, 256):
                    x_start = start_x if y == start_y and self.mode == "resume" else 0
                    for x in range(x_start, 256):
                        ip_list.append(f"{base_ip[0]}.{base_ip[1]}.{y}.{x}")
                        if len(ip_list) >= batch_size:
                            yield ip_list
                            ip_list = []
                    if ip_list:
                        yield ip_list
            elif 24 >= self.host_bits > 16:
                # 10.Z.Y.X

                start_x = start_ip[3] if start_ip else 0
                start_y = start_ip[2] if start_ip else 0
                start_z = start_ip[1] if start_ip else 0
                for z in range(start_z, 256):
                    y_start = start_y if z == start_z and self.mode == "resume" else 0
                    for y in range(y_start, 256):
                        x_start = start_x if y == start_y and self.mode == "resume" else 0
                        for x in range(x_start, 256):
                            ip_list.append(f"{base_ip[0]}.{z}.{y}.{x}")
                            if len(ip_list) >= batch_size:
                                yield ip_list
                                ip_list = []
                        if ip_list:
                            yield ip_list

        return chunked_ips()

    def set_progressbar(self, mode, filename, ip, stdscr):
        """Check if the host is alive using asynchronous pings and update UI"""
        if self.shutdown_event.is_set():
            return
        try:
            is_alive = self.start_async_ping(ip)  # self.ping_hosts(ip)
            with self.lock:  # Prevents concurrent writes
                filename_ = self.generate_filename(mode, is_alive, filename)
                self.progress_bar.update_ips(
                    self.save_to_csv, filename_, mode, ip, is_alive, stdscr, self.existing_unresponsive_ips)
                # Update live IP count on screen
                self.live_ip_count = len(self.progress_bar.live_hosts)
                stdscr.addstr(3, 0, f"Live IPs found: {self.live_ip_count}")
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
            start_ip_int = (octets[0] << 24) + (octets[1] << 16)\
                + (octets[2] << 8) + octets[3]

            # Calculate last IP in subnet
            last_ip_int = self.network_base_int + total_hosts - 1
            # Calculate remaining hosts
            return last_ip_int - start_ip_int + 1

        except Exception as e:
            self.print_error_message(exception_error=e)

# TODO: include interface check before scanning
# TODO: sort keyboard interrupt curses
# TODO: duplication in loop
