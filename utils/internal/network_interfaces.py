"""Network interface helpers used by internal scanning."""

from __future__ import annotations

from typing import List

try:
    import netifaces
except ModuleNotFoundError:
    netifaces = None


def get_interface_ip(interface: str) -> str | None:
    """Get the IPv4 address of the specified interface."""
    if netifaces is None:
        return None
    try:
        addresses = netifaces.ifaddresses(interface)
        ipv4_entries = addresses.get(netifaces.AF_INET, [])
        for addr in ipv4_entries:
            ip_addr = addr.get("addr")
            if ip_addr and ip_addr != "127.0.0.1" and not ip_addr.startswith("169."):
                return ip_addr
    except (ValueError, KeyError):
        return None
    return None


def is_interface_active(interface: str, initial_interface_ip: str | None = None) -> bool:
    """Check if the interface is up and, if provided, still on the original IP."""
    current_ip = get_interface_ip(interface)
    if not current_ip:
        return False
    if initial_interface_ip and current_ip != initial_interface_ip:
        return False
    return True


def get_active_interface() -> str | None:
    """Return the default IPv4 interface name if available."""
    if netifaces is None:
        return None
    try:
        default_gateway = netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
        if not default_gateway:
            return None
        # Tuple form: (gateway_ip, interface_name, ...)
        return default_gateway[1]
    except (KeyError, IndexError, TypeError, AttributeError):
        return None


def get_network_interfaces() -> List[str]:
    """Get all interface names reported by netifaces."""
    if netifaces is None:
        return []
    return netifaces.interfaces()
