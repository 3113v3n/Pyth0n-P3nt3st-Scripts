class NetworkHandler:
    """Class will handle any logic necessary for network operations"""

    def __init__(self) -> None:
        self.subnet = "10.1.1.2/24"
        self.hosts = 0
        self.start_ip = "0.0.0.0"  # IP to start scan from
        self.cidr = "24"
        self.user_ip_addr = "10.1.1.2"
        self.host_bits = 0

    def initialize_network_variables(self, variables):
        self.subnet = variables["subnet"]
        network_info = get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.user_ip_addr = network_info["ip_address"]
        self.cidr = network_info["cidr"]
        self.host_bits = network_info["host_bits"]

    def scan_diff_subnets(self):
        """
        Depending on the subnet provided, Scan the total number of hosts
        alive starting from the first ip in the network range

            Example: subnet = 192.168.24.10/24
                    start_ip = 192.168.24.0 - 192.168.24.255

            scan the remaining bits = 8
            hosts = 255
            hence scan 192.168.24.[0-255]
        """
        # ip_addr = self.user_ip_addr
        # cidr = self.cidr
        # host_bits = self.host_bits
        return {
            "ip_addr": self.user_ip_addr,
            "cidr": self.cidr,
            "host_bits": self.host_bits,
            "total_hosts": self.hosts,
            "usable_hosts": self.hosts - 2,
        }


def get_network_info(subnet):
    # determine num of hosts from IP addr
    # 2^(remaining bits)-2 = usable_hosts
    cidr = subnet.split("/")[1]
    bits = 32 - int(cidr)
    ip_info = {
        "ip_address": subnet.split("/")[0],
        "hosts": (2**bits),  # - 2
        "cidr": int(cidr),
        "host_bits": bits,
    }
    return ip_info
