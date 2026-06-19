from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any

from .validators import Validator


class ProgressBar(Validator):
    """Thread-safe internal scan progress tracker for OpenTUI displays."""

    def __init__(self) -> None:
        super().__init__()
        self.total_scanned = 0
        self.total_hosts = 0
        self.live_hosts: set[str] = set()
        self.unresponsive_hosts: set[str] = set()
        self.mode = "scan"
        self.subnet = ""
        self.interface = ""
        self.status_message = "Preparing scan..."
        self.last_scanned_ip = ""
        self.started_at = time.monotonic()
        self.finished = False
        self.interrupted = False
        self.recent_live: deque[str] = deque(maxlen=18)
        self.recent_unresponsive: deque[str] = deque(maxlen=18)
        self._lock = threading.Lock()

    def configure(self, *, mode: str, subnet: str, interface: str) -> None:
        with self._lock:
            self.mode = mode
            self.subnet = subnet
            self.interface = interface
            self.status_message = "Preparing scan..."
            self.last_scanned_ip = ""
            self.started_at = time.monotonic()
            self.finished = False
            self.interrupted = False
            self.total_scanned = 0
            self.total_hosts = 0
            self.live_hosts.clear()
            self.unresponsive_hosts.clear()
            self.recent_live.clear()
            self.recent_unresponsive.clear()

    def set_total_hosts(self, total: int) -> None:
        with self._lock:
            self.total_hosts = max(0, int(total))

    def set_status_message(self, message: str) -> None:
        with self._lock:
            self.status_message = str(message or "")

    def mark_finished(self, *, interrupted: bool = False) -> None:
        with self._lock:
            self.finished = True
            self.interrupted = bool(interrupted)
            if interrupted:
                self.status_message = "Scan interrupted. Review partial results below."
            else:
                self.status_message = "Scan completed. Review responsive and unresponsive hosts below."

    def _append_recent(self, bucket: deque[str], ip: str) -> None:
        if ip in bucket:
            try:
                bucket.remove(ip)
            except ValueError:
                pass
        bucket.appendleft(ip)

    def update_ips(
        self,
        filename: str,
        mode: str,
        ip: str,
        is_alive: bool,
        save_file: Callable[[str, str], Any],
        generate_filename: Callable[[str, bool, str], str],
        existing_unresponsive_ips: set,
    ) -> None:
        """Update scan progress and persist live/unresponsive host outputs."""
        filename_ = generate_filename(mode, is_alive, filename)

        if is_alive:
            save_file(filename_, ip)
        else:
            should_save = mode == "scan" or (mode == "resume" and ip not in existing_unresponsive_ips)
            if should_save:
                save_file(filename_, ip)
                if mode == "resume":
                    existing_unresponsive_ips.add(ip)

        with self._lock:
            if is_alive:
                self.live_hosts.add(ip)
                self._append_recent(self.recent_live, ip)
            else:
                self.unresponsive_hosts.add(ip)
                self._append_recent(self.recent_unresponsive, ip)
            self.total_scanned += 1
            self.last_scanned_ip = ip
            host_state = "responsive" if is_alive else "unresponsive"
            self.status_message = f"Scanned {ip} — marked {host_state}."

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            elapsed = max(0.0, time.monotonic() - self.started_at)
            total_hosts = max(0, self.total_hosts)
            total_scanned = max(0, self.total_scanned)
            progress_ratio = (total_scanned / total_hosts) if total_hosts else 0.0
            return {
                "mode": self.mode,
                "subnet": self.subnet,
                "interface": self.interface,
                "status_message": self.status_message,
                "last_scanned_ip": self.last_scanned_ip,
                "total_scanned": total_scanned,
                "total_hosts": total_hosts,
                "live_count": len(self.live_hosts),
                "unresponsive_count": len(self.unresponsive_hosts),
                "recent_live": list(self.recent_live),
                "recent_unresponsive": list(self.recent_unresponsive),
                "progress_ratio": progress_ratio,
                "elapsed_seconds": elapsed,
                "finished": self.finished,
                "interrupted": self.interrupted,
            }
