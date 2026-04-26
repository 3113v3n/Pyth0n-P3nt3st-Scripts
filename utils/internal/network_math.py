"""IP/network math helpers for internal scanning."""

from __future__ import annotations

import ipaddress
from typing import Iterator


def get_network_info(subnet: str) -> dict:
    """Return normalized network metadata for a subnet string (e.g. 10.0.0.5/24)."""
    interface = ipaddress.ip_interface(subnet)
    network = interface.network
    mask = network.prefixlen
    host_bits = network.max_prefixlen - mask
    return {
        "ip_address": str(interface.ip),
        "hosts": network.num_addresses,
        "network_mask": mask,
        "host_bits": host_bits,
        "network_base_address": int(network.network_address),
    }


def calculate_remaining_hosts(
    ip_string: str,
    total_hosts: int,
    network_base_address: int,
) -> int:
    """Calculate remaining host count from *ip_string* to subnet end, inclusive."""
    start_ip_int = int(ipaddress.ip_address(ip_string))
    last_ip_int = network_base_address + total_hosts - 1
    return max(0, (last_ip_int - start_ip_int + 1))


def generate_ip_batches(
    subnet: str,
    start_ip: str | None = None,
    batch_size: int = 2000,
) -> Iterator[list[str]]:
    """Yield subnet IPs in batches from *start_ip* (or network start) to broadcast."""
    network = ipaddress.ip_network(subnet, strict=False)
    current_ip = ipaddress.ip_address(start_ip) if start_ip else network.network_address

    if current_ip not in network:
        raise ValueError(f"Start IP {current_ip} is outside subnet {subnet}")

    batch: list[str] = []
    for ip_int in range(int(current_ip), int(network.broadcast_address) + 1):
        batch.append(str(ipaddress.ip_address(ip_int)))
        if len(batch) >= batch_size:
            yield batch
            batch = []

    if batch:
        yield batch
