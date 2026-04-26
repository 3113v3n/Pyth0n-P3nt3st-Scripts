"""Network scanning orchestration for internal assessment."""

from __future__ import annotations

import curses
import os
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from handlers import FileHandler
from utils.internal.network_constants import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_WORKER_CAP,
    DEFAULT_PROGRESS_CHUNK,
    DEFAULT_WORKER_MULTIPLIER,
    INTERFACE_POLL_INTERVAL_SECONDS,
)
from utils.internal.network_interfaces import (
    get_active_interface as resolve_active_interface,
    get_interface_ip as resolve_interface_ip,
    get_network_interfaces as resolve_network_interfaces,
    is_interface_active,
)
from utils.internal.network_math import (
    calculate_remaining_hosts as get_remaining_hosts,
    generate_ip_batches,
    get_network_info,
)
from utils.shared import Commands


class NetworkHandler(FileHandler, Commands):
    """Handle internal network scanning state and orchestration."""

    def __init__(self) -> None:
        super().__init__()
        self.subnet = ""
        self.hosts = 0
        self.start_ip = ""
        self.network_mask = ""
        self.user_ip_addr = ""
        self.host_bits = 0
        self.ip_alive = False
        self.mode = "scan"
        self.network_base_address = 0
        self.progress_bar = None
        self.live_ip_count = 0
        self.scan_complete = False
        self.scan_thread = None
        self.monitor_thread = None
        self.interface = None
        self.is_interface_active = False
        self.initial_interface_ip = None
        self.debug = False
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()

    def reset_state(self) -> None:
        """Reset instance state to defaults between runs."""
        self.subnet = ""
        self.hosts = 0
        self.start_ip = ""
        self.network_mask = ""
        self.user_ip_addr = ""
        self.host_bits = 0
        self.mode = "scan"
        self.progress_bar = None
        self.scan_thread = None
        self.interface = None
        self.is_interface_active = False
        self.lock = threading.Lock()
        self.shutdown_event = threading.Event()
        self.scan_complete = False

    @classmethod
    def reset_class_states(cls):
        """Deprecated compatibility method; use reset_state() on the instance."""
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
        """Initialize scan variables from user/domain input."""
        self.subnet = variables["subnet"]
        self.interface = variables["interface"]
        network_info = get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.mode = variables["action"]
        self.user_ip_addr = network_info["ip_address"]
        self.network_mask = network_info["network_mask"]
        self.host_bits = network_info["host_bits"]
        self.network_base_address = network_info["network_base_address"]
        self.progress_bar = progress_bar()
        self.update_output_directory(test_domain)
        self.initial_interface_ip = self.get_interface_ip(self.interface)

    @staticmethod
    def get_interface_ip(interface: str) -> str | None:
        return resolve_interface_ip(interface)

    def port_discovery(self):
        # use masscan to discover open ports if ICMP is blocked
        pass

    def generate_filename(self, mode: str, is_alive: bool, filename: str) -> str:
        """Generate output filename for live/unresponsive host lists."""
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

    def scan_network(self, stdscr, mode: str, output_file: str):
        """Scan network hosts and update progress/output files."""
        stdscr.clear()
        stdscr.addstr(0, 0, "Network Scanner - Press Ctrl+C to stop")
        stdscr.refresh()
        curses.curs_set(0)
        curses.echo(False)

        if not self.interface:
            self.interface = resolve_active_interface()
            if not self.interface:
                stdscr.addstr(4, 0, "No active interface found.")
                stdscr.refresh()
                curses.napms(1000)
                return

        current_ip = self.get_interface_ip(self.interface)
        if not current_ip:
            stdscr.addstr(4, 0, f"Interface {self.interface} has no valid IP.")
            stdscr.refresh()
            curses.napms(1000)
            return

        self.initial_interface_ip = current_ip

        def signal_handler(sig, frame):
            self.shutdown_event.set()
            stdscr.addstr(4, 0, "Shutting down...")
            stdscr.refresh()
            curses.napms(250)

        signal.signal(signal.SIGINT, signal_handler)

        try:
            self.mode = mode
            remaining_hosts = (
                self.calculate_remaining_hosts(self.user_ip_addr)
                if self.mode == "resume"
                else self.hosts
            )
            total = max(0, remaining_hosts)
            processed = 0
            committed_progress = 0

            cpu_count = os.cpu_count() or 2
            max_workers = min(
                DEFAULT_MAX_WORKER_CAP,
                max(2, cpu_count * DEFAULT_WORKER_MULTIPLIER),
            )

            self.monitor_thread = threading.Thread(
                target=self.monitor_interface,
                args=(stdscr,),
                daemon=True,
            )
            self.monitor_thread.start()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                with tqdm(total=total, desc="Scanning", file=sys.stdout, leave=False) as pbar:
                    for ip_batch in self.generate_ip_in_batches():
                        if self.shutdown_event.is_set():
                            break

                        futures = {
                            executor.submit(
                                self.set_progressbar,
                                mode,
                                output_file,
                                ip,
                                stdscr,
                            ): ip
                            for ip in ip_batch
                        }

                        for _ in as_completed(futures):
                            if self.shutdown_event.is_set():
                                break

                            processed += 1
                            if (
                                processed % DEFAULT_PROGRESS_CHUNK == 0
                                or processed == total
                            ):
                                delta = processed - committed_progress
                                if delta > 0:
                                    pbar.update(delta)
                                    committed_progress = processed

                    if processed > committed_progress:
                        pbar.update(processed - committed_progress)

            self.scan_complete = not self.shutdown_event.is_set()
        except Exception as error:
            stdscr.addstr(4, 0, f"Error: {error}")
            stdscr.refresh()
            curses.napms(1000)
            self.scan_complete = False
        finally:
            print("Final cleanup...")
            self.shutdown_event.set()
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)

    def get_live_ips(self, output: str) -> int:
        """Run the curses scanner and return discovered live host count."""
        try:
            curses.wrapper(self.scan_network, self.mode, output)
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except KeyboardInterrupt:
            print("\nProgram terminated by user.")
            self.scan_complete = False
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except Exception as error:
            self.print_error_message(exception_error=error)
            self.scan_complete = False
            return 0

    def generate_ip_in_batches(self, batch_size: int = DEFAULT_BATCH_SIZE):
        """Yield IP addresses in batches for current mode/subnet."""
        if self.mode == "resume":
            self.hosts = self.calculate_remaining_hosts(self.user_ip_addr)
            start_ip = self.user_ip_addr
        else:
            start_ip = None

        self.progress_bar.set_total_hosts(self.hosts)
        return generate_ip_batches(
            subnet=self.subnet,
            start_ip=start_ip,
            batch_size=batch_size,
        )

    def set_progressbar(self, mode, filename, ip, stdscr):
        """Ping host and update progress/file outputs in a critical section."""
        if self.shutdown_event.is_set():
            return

        try:
            is_alive = self.start_async_ping(ip)
            with self.lock:
                self.progress_bar.update_ips(
                    filename,
                    mode,
                    ip,
                    is_alive,
                    stdscr,
                    self.save_to_csv,
                    self.generate_filename,
                    self.existing_unresponsive_ips,
                )
                self.live_ip_count = len(self.progress_bar.live_hosts)
        except Exception as error:
            self.print_error_message(
                f"set Progress bar failed for IP: {ip} : ",
                exception_error=error,
            )

    def calculate_remaining_hosts(self, ip_string: str) -> int:
        """Calculate remaining scan space from an IP to subnet broadcast."""
        return get_remaining_hosts(
            ip_string=ip_string,
            total_hosts=self.hosts,
            network_base_address=self.network_base_address,
        )

    def _is_interface_active(self, interface: str) -> bool:
        """Compatibility wrapper for existing callers."""
        return is_interface_active(interface, self.initial_interface_ip)

    def monitor_interface(self, stdscr):
        """Stop scan if interface drops or changes IP during execution."""
        while not self.shutdown_event.is_set():
            if not is_interface_active(self.interface, self.initial_interface_ip):
                with self.lock:
                    if stdscr:
                        stdscr.addstr(
                            5,
                            0,
                            f"Interface {self.interface} dropped or changed. Stopping scan.",
                        )
                        stdscr.refresh()
                    self.shutdown_event.set()
                break
            self.shutdown_event.wait(INTERFACE_POLL_INTERVAL_SECONDS)

    def kill_scan(self):
        """Stop the network scan if running."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.shutdown_event.set()
            self.scan_thread.join()
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)
            print("Scan stopped.")


def get_active_interface():
    """Compatibility helper that returns the default active interface."""
    return resolve_active_interface()


def get_network_interfaces():
    """Compatibility helper that returns all interface names."""
    return resolve_network_interfaces()
