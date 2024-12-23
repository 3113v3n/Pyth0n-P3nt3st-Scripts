import re
import os


class InputValidators:
    """Class runs validation checks on user provided input"""

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

    def check_subdirectory_exists(self, folder_name, search_path) -> bool:
        folder_exists = False
        for _, subfolder, _ in os.walk(search_path):
            if folder_name in subfolder:
                folder_exists = True
                break
        return folder_exists

    def file_exists(self, filename) -> bool:
        return os.path.isfile(filename)

    def check_filetype(self, filename: str, filetype: str) -> bool:
        pattern = re.compile(rf"\.{re.escape(filetype)}$", re.IGNORECASE)
        return bool(pattern.search(filename))

    def check_folder_exists(self, folder_path):
        # handle trailing slash issue
        norm_path = os.path.normpath(folder_path)
        return os.path.isdir(norm_path)

    def find_specific_file(self, filename, search_path):
        for root, _, files in os.walk(search_path):
            if filename in files:
                return os.path.join(root, filename)
        return None

    def remove_spaces(self, text):
        return text.replace(" ", "_")
