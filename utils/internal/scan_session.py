"""Persistent scan session metadata for internal network resume flows."""

from __future__ import annotations

import json
import os
import time
import uuid
import ipaddress
from pathlib import Path
from typing import Any

from utils.internal.network_interfaces import (
    get_interface_ip,
    get_interface_mac,
    get_network_interfaces,
)

STATE_VERSION = 1
CHECKPOINT_EVERY_HOSTS = 512
CHECKPOINT_EVERY_SECONDS = 5.0


class ScanSessionStore:
    """Store and query internal scan state snapshots."""

    def __init__(self, output_directory: str) -> None:
        self.output_directory = output_directory
        self.state_dir = Path(output_directory) / ".scan_state"
        self.index_path = self.state_dir / "index.json"
        self._last_checkpoint_ts = 0.0

    @staticmethod
    def _now() -> float:
        return time.time()

    @staticmethod
    def normalize_path(path: str) -> str:
        return str(Path(path).expanduser().resolve())

    @staticmethod
    def canonicalize_subnet(subnet: str) -> str:
        """Normalize subnet into canonical network/CIDR form when possible."""
        try:
            return str(ipaddress.ip_network(subnet, strict=False))
        except ValueError:
            return subnet

    def _ensure_state_dir(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _read_json(path: Path, default: Any) -> Any:
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return default

    def _write_json_atomic(self, path: Path, payload: dict) -> None:
        self._ensure_state_dir()
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _read_index(self) -> dict[str, str]:
        data = self._read_json(self.index_path, default={})
        return data if isinstance(data, dict) else {}

    def _write_index(self, data: dict[str, str]) -> None:
        self._write_json_atomic(self.index_path, data)

    @staticmethod
    def _interface_kind(name: str) -> str:
        lower = name.lower()
        if lower.startswith(("wl", "wlan")):
            return "wireless"
        if lower.startswith(("en", "eth")):
            return "ethernet"
        return "other"

    def build_interface_snapshot(self, interface_name: str) -> dict[str, str | None]:
        return {
            "name": interface_name,
            "mac": get_interface_mac(interface_name),
            "ipv4_at_start": get_interface_ip(interface_name),
            "if_type": self._interface_kind(interface_name),
        }

    @staticmethod
    def _is_interface_active(interface_name: str) -> bool:
        return bool(get_interface_ip(interface_name))

    def _is_similar_interface(
        self,
        saved_snapshot: dict[str, Any],
        candidate_snapshot: dict[str, Any],
    ) -> bool:
        saved_name = saved_snapshot.get("name")
        saved_mac = saved_snapshot.get("mac")
        candidate_name = candidate_snapshot.get("name")
        candidate_mac = candidate_snapshot.get("mac")

        if saved_mac and candidate_mac and saved_mac == candidate_mac:
            return True
        if saved_name and candidate_name and saved_name == candidate_name:
            return True
        return False

    def find_similar_active_interface(
        self,
        saved_snapshot: dict[str, Any],
        preferred_interface: str | None = None,
    ) -> str | None:
        candidates: list[str] = []
        if preferred_interface:
            candidates.append(preferred_interface)

        candidates.extend(
            iface
            for iface in get_network_interfaces()
            if iface not in candidates
            and not iface.startswith(("br-", "docker", "veth", "lo"))
        )

        for iface in candidates:
            if not self._is_interface_active(iface):
                continue
            snapshot = self.build_interface_snapshot(iface)
            if self._is_similar_interface(saved_snapshot, snapshot):
                return iface
        return None

    def _session_path(self, session_id: str) -> Path:
        return self.state_dir / f"{session_id}.json"

    def get_session_by_unresponsive_file(self, unresponsive_file: str) -> dict | None:
        key = self.normalize_path(unresponsive_file)
        index = self._read_index()
        session_id = index.get(key)
        if session_id:
            data = self._read_json(self._session_path(session_id), default=None)
            if isinstance(data, dict):
                return data

        for candidate in self.state_dir.glob("*.json"):
            if candidate.name == self.index_path.name:
                continue
            data = self._read_json(candidate, default=None)
            if not isinstance(data, dict):
                continue
            files = data.get("files", {})
            file_path = files.get("unresponsive_hosts")
            if file_path and self.normalize_path(file_path) == key:
                session_id = data.get("session_id")
                if isinstance(session_id, str):
                    index[key] = session_id
                    self._write_index(index)
                return data
        return None

    def create_session(
        self,
        subnet_cidr: str,
        interface_name: str,
        live_file: str,
        unresponsive_file: str,
    ) -> dict:
        session_id = str(uuid.uuid4())
        now = self._now()
        session = {
            "session_id": session_id,
            "version": STATE_VERSION,
            "status": "running",
            "subnet_cidr": self.canonicalize_subnet(subnet_cidr),
            "interface_snapshot": self.build_interface_snapshot(interface_name),
            "files": {
                "live_hosts": self.normalize_path(live_file),
                "unresponsive_hosts": self.normalize_path(unresponsive_file),
            },
            "checkpoint": {
                "last_scanned_ip": None,
                "scanned_count": 0,
                "live_count": 0,
                "unresponsive_count": 0,
                "updated_at": now,
            },
            "created_at": now,
            "updated_at": now,
            "finished_at": None,
        }
        self._write_json_atomic(self._session_path(session_id), session)

        index = self._read_index()
        index[self.normalize_path(unresponsive_file)] = session_id
        self._write_index(index)
        return session

    def save_session(self, session: dict) -> None:
        session["updated_at"] = self._now()
        session_id = session.get("session_id")
        if not isinstance(session_id, str):
            return
        self._write_json_atomic(self._session_path(session_id), session)

    def mark_status(self, session: dict, status: str) -> None:
        now = self._now()
        session["status"] = status
        session["updated_at"] = now
        if status == "completed":
            session["finished_at"] = now
        self.save_session(session)

    def should_checkpoint(self, processed: int) -> bool:
        now = time.monotonic()
        if processed % CHECKPOINT_EVERY_HOSTS == 0:
            self._last_checkpoint_ts = now
            return True
        if (now - self._last_checkpoint_ts) >= CHECKPOINT_EVERY_SECONDS:
            self._last_checkpoint_ts = now
            return True
        return False

    def update_checkpoint(
        self,
        session: dict,
        last_scanned_ip: str,
        scanned_count: int,
        live_count: int,
        unresponsive_count: int,
        force: bool = False,
    ) -> None:
        if not session:
            return

        if not force and not self.should_checkpoint(scanned_count):
            return

        checkpoint = session.setdefault("checkpoint", {})
        checkpoint["last_scanned_ip"] = last_scanned_ip
        checkpoint["scanned_count"] = scanned_count
        checkpoint["live_count"] = live_count
        checkpoint["unresponsive_count"] = unresponsive_count
        checkpoint["updated_at"] = self._now()
        self.save_session(session)
