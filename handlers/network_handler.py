"""Network scanning orchestration for internal assessment."""

from __future__ import annotations

import ipaddress
import os
import signal
import threading
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

from handlers import FileHandler
from utils.internal.network_constants import (
    DEFAULT_BATCH_SIZE,
    DEFAULT_MAX_WORKER_CAP,
    DEFAULT_WORKER_MULTIPLIER,
    INTERFACE_POLL_INTERVAL_SECONDS,
)
from utils.internal.network_interfaces import (
    get_active_interface as resolve_active_interface,
)
from utils.internal.network_interfaces import (
    get_interface_ip as resolve_interface_ip,
)
from utils.internal.network_interfaces import (
    get_network_interfaces as resolve_network_interfaces,
)
from utils.internal.network_interfaces import (
    is_interface_active,
)
from utils.internal.network_math import (
    calculate_remaining_hosts as get_remaining_hosts,
)
from utils.internal.network_math import (
    generate_ip_batches,
    get_network_info,
)
from utils.internal.scan_session import ScanSessionStore
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
        self.session_store: ScanSessionStore | None = None
        self.current_scan_session: dict | None = None
        self.last_scanned_ip: str | None = None
        self.resume_scanned_ips: set[str] = set()
        self._shutdown_notice_displayed = False

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
        self.session_store = None
        self.current_scan_session = None
        self.last_scanned_ip = None
        self.resume_scanned_ips = set()
        self._shutdown_notice_displayed = False

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
        cls.session_store = None
        cls.current_scan_session = None
        cls.last_scanned_ip = None
        cls.resume_scanned_ips = set()
        cls._shutdown_notice_displayed = False

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
        self.session_store = ScanSessionStore(self.output_directory)
        self.current_scan_session = None
        self.last_scanned_ip = None
        self.resume_scanned_ips = set()

    @staticmethod
    def get_interface_ip(interface: str) -> str | None:
        return resolve_interface_ip(interface)

    def _resolve_output_path(self, filename: str) -> str:
        """Resolve scan output filename to an absolute path."""
        path = Path(filename)
        if not path.is_absolute():
            path = Path(self.output_directory) / path.name
        return str(path.resolve())

    def _initialize_scan_session(self, mode: str, output_file: str) -> None:
        """Initialize persisted scan session state for scan/resume flows."""
        if not self.session_store:
            return

        if mode == "scan":
            live_path = self._resolve_output_path(
                self.generate_filename(mode, True, output_file)
            )
            unresponsive_path = self._resolve_output_path(
                self.generate_filename(mode, False, output_file)
            )
            self.current_scan_session = self.session_store.create_session(
                subnet_cidr=self.subnet,
                interface_name=self.interface or "",
                live_file=live_path,
                unresponsive_file=unresponsive_path,
            )
            return

        # Resume mode: try to bind to an existing session if present.
        resume_path = self._resolve_output_path(output_file)
        session = self.session_store.get_session_by_unresponsive_file(resume_path)
        if session:
            session["status"] = "running"
            self.session_store.save_session(session)
            self.current_scan_session = session

    @staticmethod
    def _derive_live_file_from_unresponsive(unresponsive_file: str) -> str:
        """Map '*_unresponsive_hosts.csv' to its matching live-host CSV path."""
        path = Path(unresponsive_file)
        suffix = "_unresponsive_hosts"
        stem = path.stem
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
        return str(path.with_name(f"{stem}{path.suffix or '.csv'}"))

    @staticmethod
    def _read_ips_from_file(file_path: str) -> set[str]:
        """Load newline-delimited IP strings from a file, best-effort."""
        ips: set[str] = set()
        if not file_path:
            return ips
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    ip = line.strip()
                    if ip:
                        ips.add(ip.split(",")[0].strip())
        except OSError:
            return ips
        return ips

    def _load_resume_scanned_ips(self, output_file: str) -> None:
        """Load all previously scanned IPs for resume (live + unresponsive)."""
        unresponsive_file = self._resolve_output_path(output_file)
        live_file = self._derive_live_file_from_unresponsive(unresponsive_file)

        if self.current_scan_session:
            files = self.current_scan_session.get("files", {})
            live_file = files.get("live_hosts", live_file)
            unresponsive_file = files.get("unresponsive_hosts", unresponsive_file)

        prior_live = self._read_ips_from_file(live_file)
        prior_unresponsive = self._read_ips_from_file(unresponsive_file)
        self.existing_unresponsive_ips = set(prior_unresponsive)

        network = ipaddress.ip_network(self.subnet, strict=False)
        scanned: set[str] = set()
        for ip in prior_live.union(prior_unresponsive):
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip_obj in network:
                scanned.add(str(ip_obj))
        self.resume_scanned_ips = scanned

    def _calculate_resume_pending_hosts(self) -> int:
        """Return number of IPs still pending for resume mode."""
        if self.mode != "resume":
            return self.hosts
        return max(0, self.hosts - len(self.resume_scanned_ips))

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

    def scan_network(self, mode: str, output_file: str):
        """Scan network hosts and update progress/output files."""
        if self.progress_bar is not None:
            self.progress_bar.configure(
                mode=mode,
                subnet=self.subnet,
                interface=self.interface or resolve_active_interface() or "pending",
            )
            self.progress_bar.set_status_message("Preparing scan context...")

        if not self.interface:
            self.interface = resolve_active_interface()
            if self.progress_bar is not None:
                self.progress_bar.set_status_message(
                    f"Using active interface: {self.interface or 'not found'}"
                )
            if not self.interface:
                self.scan_complete = False
                return

        current_ip = self.get_interface_ip(self.interface)
        if not current_ip:
            if self.progress_bar is not None:
                self.progress_bar.set_status_message(
                    f"Interface {self.interface} has no valid IP."
                )
                self.progress_bar.mark_finished(interrupted=True)
            self.scan_complete = False
            return

        self.initial_interface_ip = current_ip
        self.last_scanned_ip = None
        self._initialize_scan_session(mode, output_file)
        if mode == "resume":
            self._load_resume_scanned_ips(output_file)

        def display_shutdown_notice() -> None:
            if self._shutdown_notice_displayed:
                return
            self._shutdown_notice_displayed = True
            if self.progress_bar is not None:
                self.progress_bar.set_status_message(
                    "Shutting down... cancelling pending hosts."
                )

        previous_sigint_handler = None
        manage_signals = threading.current_thread() is threading.main_thread()

        def signal_handler(sig, frame):
            self.shutdown_event.set()

        if manage_signals:
            previous_sigint_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal_handler)

        executor: ThreadPoolExecutor | None = None
        futures: dict = {}
        interrupted = False
        try:
            self.mode = mode
            processed = 0

            cpu_count = os.cpu_count() or 2
            max_workers = min(
                DEFAULT_MAX_WORKER_CAP,
                max(2, cpu_count * DEFAULT_WORKER_MULTIPLIER),
            )

            self.monitor_thread = threading.Thread(
                target=self.monitor_interface,
                daemon=True,
            )
            self.monitor_thread.start()

            executor = ThreadPoolExecutor(max_workers=max_workers)
            for ip_batch in self.generate_ip_in_batches():
                if self.shutdown_event.is_set():
                    interrupted = True
                    display_shutdown_notice()
                    break

                futures = {
                    executor.submit(
                        self.set_progressbar,
                        mode,
                        output_file,
                        ip,
                    ): ip
                    for ip in ip_batch
                }
                pending = set(futures)

                while pending:
                    if self.shutdown_event.is_set():
                        interrupted = True
                        display_shutdown_notice()
                        for future in pending:
                            future.cancel()
                        break

                    done, pending = wait(
                        pending,
                        timeout=0.2,
                        return_when=FIRST_COMPLETED,
                    )
                    if not done:
                        continue

                    for future in done:
                        ip = futures[future]
                        self.last_scanned_ip = ip
                        processed += 1
                        if self.current_scan_session and self.session_store and self.progress_bar:
                            live_count = len(self.progress_bar.live_hosts)
                            dead_count = len(self.progress_bar.unresponsive_hosts)
                            self.session_store.update_checkpoint(
                                session=self.current_scan_session,
                                last_scanned_ip=ip,
                                scanned_count=processed,
                                live_count=live_count,
                                unresponsive_count=dead_count,
                            )

                if interrupted:
                    break

            self.scan_complete = not self.shutdown_event.is_set()
            if self.progress_bar is not None:
                self.progress_bar.mark_finished(interrupted=not self.scan_complete)
        except Exception as error:
            if self.progress_bar is not None:
                self.progress_bar.set_status_message(f"Error: {error}")
                self.progress_bar.mark_finished(interrupted=True)
            self.scan_complete = False
        finally:
            if manage_signals and previous_sigint_handler is not None:
                signal.signal(signal.SIGINT, previous_sigint_handler)
            if executor is not None:
                for future in futures:
                    future.cancel()
                executor.shutdown(
                    wait=True,
                    cancel_futures=True,
                )
            if self.shutdown_event.is_set():
                display_shutdown_notice()
            self.shutdown_event.set()
            if self.monitor_thread:
                self.monitor_thread.join(timeout=2)
            if self.current_scan_session and self.session_store:
                live_count = len(self.progress_bar.live_hosts) if self.progress_bar else 0
                dead_count = (
                    len(self.progress_bar.unresponsive_hosts)
                    if self.progress_bar
                    else 0
                )
                self.session_store.update_checkpoint(
                    session=self.current_scan_session,
                    last_scanned_ip=self.last_scanned_ip or "",
                    scanned_count=live_count + dead_count,
                    live_count=live_count,
                    unresponsive_count=dead_count,
                    force=True,
                )
                final_status = "completed" if self.scan_complete else "interrupted"
                self.session_store.mark_status(self.current_scan_session, final_status)

    def get_live_ips(self, output: str) -> int:
        """Run the network scan and return discovered live host count."""
        try:
            from handlers.opentui_menu import opentui_menu_enabled
            from handlers.screen import ScreenHandler

            if self.progress_bar is None:
                return 0

            if opentui_menu_enabled():
                ScreenHandler.show_progress_viewer(
                    title="Internal Network Progress",
                    prompt="Responsive and unresponsive hosts update live while the scan runs.",
                    subtitle="Internal scan/resume workflow with OpenTUI progress tracking",
                    snapshot_getter=self.progress_bar.snapshot,
                    worker=lambda: self.scan_network(self.mode, output),
                    cancel=self.shutdown_event.set,
                )
            else:
                self.scan_network(self.mode, output)
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except KeyboardInterrupt:
            self.shutdown_event.set()
            self.scan_complete = False
            if self.progress_bar is not None:
                self.progress_bar.mark_finished(interrupted=True)
            return len(self.progress_bar.live_hosts) if self.progress_bar else 0
        except Exception as error:
            self.print_error_message(exception_error=error)
            self.scan_complete = False
            if self.progress_bar is not None:
                self.progress_bar.mark_finished(interrupted=True)
            return 0

    def generate_ip_in_batches(self, batch_size: int = DEFAULT_BATCH_SIZE):
        """Yield IP addresses in batches for current mode/subnet."""
        pending_hosts = (
            self._calculate_resume_pending_hosts()
            if self.mode == "resume"
            else self.hosts
        )
        self.progress_bar.set_total_hosts(pending_hosts)

        for ip_batch in generate_ip_batches(
            subnet=self.subnet,
            start_ip=None,
            batch_size=batch_size,
        ):
            if self.mode != "resume" or not self.resume_scanned_ips:
                yield ip_batch
                continue

            pending_batch = [ip for ip in ip_batch if ip not in self.resume_scanned_ips]
            if pending_batch:
                yield pending_batch

    def set_progressbar(self, mode, filename, ip):
        """Ping host and update progress/file outputs in a critical section."""
        if self.shutdown_event.is_set():
            return

        try:
            is_alive = self.start_async_ping(ip)
            if self.shutdown_event.is_set():
                return
            with self.lock:
                self.progress_bar.update_ips(
                    filename,
                    mode,
                    ip,
                    is_alive,
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

    def monitor_interface(self):
        """Stop scan if interface drops or changes IP during execution."""
        while not self.shutdown_event.is_set():
            try:
                active = is_interface_active(self.interface, self.initial_interface_ip)
            except Exception as error:
                with self.lock:
                    if self.progress_bar is not None:
                        self.progress_bar.set_status_message(
                            f"Interface monitor failed. Stopping scan: {error}"
                        )
                    self.shutdown_event.set()
                break

            if not active:
                with self.lock:
                    if self.progress_bar is not None:
                        self.progress_bar.set_status_message(
                            f"Interface {self.interface} dropped or changed. Stopping scan."
                        )
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
            if self.progress_bar is not None:
                self.progress_bar.mark_finished(interrupted=True)
                self.progress_bar.set_status_message("Scan stopped by operator request.")


def get_active_interface():
    """Compatibility helper that returns the default active interface."""
    return resolve_active_interface()


def get_network_interfaces():
    """Compatibility helper that returns all interface names."""
    return resolve_network_interfaces()
