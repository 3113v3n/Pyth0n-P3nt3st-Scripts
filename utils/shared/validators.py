import re
import os


def validate_ip_addr(addr) -> bool:
    # 10.0.0.0
    ipv4_pattern = re.compile(
        r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    return ipv4_pattern.match(addr) is not None


def check_subdirectory_exists(folder_name, search_path) -> bool:
    folder_exists = False
    for _, subfolder, _ in os.walk(search_path):
        if folder_name in subfolder:
            folder_exists = True
            break
    return folder_exists


def get_filename_without_extension(filepath):
    # Get the filename with extension
    filename_with_ext = os.path.basename(filepath)
    # Split the filename and extension
    filename_without_ext, _ = os.path.splitext(filename_with_ext)
    return filename_without_ext


def validate_ip_and_cidr(ip_address) -> bool:
    # 10.0.0.1/8
    pattern = (r"^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])/(3["
               r"0-2]|[1-2]?[1-9]|[1-9])$")
    return bool(re.match(pattern, ip_address))


def validate_cidr(cidr) -> bool:
    """
    ^ and $ --> ensure entire string is matched
    (?: ...) --> groups options
        [0-9] --> matches digits from 0 to 9
        [1-2][0-9] --> matches digits from 10 to 29
        3[0-2] --> matches digits from 30 to 32
    """
    pattern = r"^(?:[0-9]|[1-2][0-9]|3[0-2])$"
    return bool(re.match(pattern, cidr))


def file_exists(filename) -> bool:
    exists = os.path.isfile(filename)
    return exists


def check_filetype(filename: str, filetype: str) -> bool:
    pattern = re.compile(rf"\.{re.escape(filetype)}$", re.IGNORECASE)
    return bool(pattern.search(filename))


def check_folder_exists(folder_path):
    # handle trailing slash issue
    norm_path = os.path.normpath(folder_path)
    return os.path.isdir(norm_path)


def find_specific_file(filename, search_path):
    for root, _, files in os.walk(search_path):
        if filename in files:
            return os.path.join(root, filename)
    return None


def remove_spaces(text):
    return text.replace(" ", "_")
