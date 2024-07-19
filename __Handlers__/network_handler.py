from ipaddress import ip_interface,ip_network,IPv4Address


class NetworkHandler:
    """Class will handle any logic necessary for network operations"""

    def __init__(self) -> None:
        self.subnet = ""                    # subnet range
        self.hosts = 0                      # Number of hosts within the network
        self.start_ip = ""                  # IP to start scan from
        self.cidr = ""                      # CIDR value [0-32]
        self.user_ip_addr = ""              # user IP addr
        self.host_bits = 0                  # remaining usable host bits

    def initialize_network_variables(self, variables):
        # initialize the class variables with user variables
        self.subnet = variables["subnet"]
        network_info = get_network_info(self.subnet)
        self.hosts = network_info["hosts"]
        self.user_ip_addr = network_info["ip_address"]
        self.cidr = network_info["cidr"]
        self.host_bits = network_info["host_bits"]

    def get_all_ips(self):
        """
        Depending on the subnet provided, Scan the total number of hosts
        alive starting from the first ip in the network range

            Example: subnet = 192.168.24.10/24
                    start_ip = 192.168.24.0 - 192.168.24.255

            scan the remaining bits = 8
            hosts = 255
            hence scan 192.168.24.[0-255]
        """
        print(f"Total Hosts: {self.hosts}")
        try:
            interface = ip_interface(self.subnet)
            ip = interface.ip
            network = ip_network(f"{ip}/{interface.network.prefixlen}", strict=False)
            all_ips = []
            # [str(ip) for ip in network.hosts()] --> returns only usable hosts
            if network.prefixlen <= 24:
                for i in range(256):
                    all_ips.append(str(IPv4Address(f"{IPv4Address(int(ip) & ~0xFF | i)}")))
            else:
                all_ips = [str(ip) for ip in network]
            
            return all_ips
        except ValueError as e:
            return str(e)
        

    def generate_possible_ips(self,subnet):
        pass


def get_network_info(subnet)->dict:
    """ Function takes in network subnet and splits the provided
        Values into an ip address and subnet.
        It then returns a dictionary containing 
        {
        ip address,
        number of hosts,
        cidr value,
        number of host bits
        }
    """
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
