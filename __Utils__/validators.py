import re


class Validators:
    def __init__(self) -> None:
        pass

    def validate_cidr(self, cidr) -> bool:
        # 10.0.0.1/8
        pattern = r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3[0-2]|[1-2]?[1-9]|[1-9])$"
        return bool(re.match(pattern, cidr))

    def validate_ip_addr(self, addr) -> bool:
        # 10.0.0.0
        ipv4_pattern = re.compile(
            r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        )
        return ipv4_pattern.match(addr) is not None

    def directory_exists(self, path_to_directory) -> bool:
        return True

    def file_exists(self, filename) -> bool:
        return True
