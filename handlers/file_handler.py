import os
from datetime import datetime
from pathlib import Path


class FileHandler:
    """Handle File operations"""

    def __init__(self) -> None:
        self.test_domain = ""  # one of [internal,external,mobile]
        self.output_directory = (
            "./output_directory"  # directory to save our output files
        )
        self.full_file_path = ""  # full path to saved file

    def update_output_directory(self, domain):
        """
        Depending on the test domain provided
        we update the output directory for various file output
        """
        match domain:
            case "mobile":
                self.output_directory = f"{self.output_directory}/mobile"
                return self.output_directory
            case "internal":
                self.output_directory = f"{self.output_directory}/internal"
                return self.output_directory
            case "external":
                self.output_directory = f"{self.output_directory}/external"
                return self.output_directory
            case _:
                return

    def save_new_file(self, filename, content):
        self.full_file_path = f"{self.output_directory}/{filename}"
        with open(f"{self.output_directory}/{filename}", "a") as file:
            file.write(f"{content}\n")

    def append_file(self, filename, content):
        """Update existing file"""
        with open(f"{self.output_directory}/{filename}", "a") as file:
            file.write(f"{content}\n")

    def find_file(self, filename):
        """
        Searches for a file in the given directory and its subdirectories.

        :param filename: Name of the file to search for.
        :param search_path: Directory to start the search from.
        :return: Full path of the file if found, None otherwise.
        """
        for root, dirs, files in os.walk("."):
            if filename in files:
                return os.path.join(root, filename)
        return None

    def read_last_line(self, filename) -> str:
        """
        Takes a filename containing a list of ips and returns
        the last ip address
        """
        with open(f"{filename}", "rb") as file:
            try:  # catch OSError in case of one line file
                file.seek(-2, os.SEEK_END)
                while file.read(1) != b"\n":
                    file.seek(-2, os.SEEK_CUR)
            except OSError:
                file.seek(0)
            last_line = file.readline().decode()
        return last_line

    def generate_unique_name(self, file) -> str:
        timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        removed_extension = Path(file).stem
        return f"{removed_extension}_{timestamp}.txt"
