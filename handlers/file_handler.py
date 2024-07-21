import os


class FileHandler:
    """Handle File operations"""

    def __init__(self) -> None:
        self.test_domain = ""  # one of [internal,external,mobile]
        self.output_directory = (
            "./output_directory"  # directory to save our output files
        )

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
        with open(f"{filename}", "w") as file:
            file.write(content)

    def append_file(self, filename, content):
        """Update existing file"""
        with open(filename, "a") as file:
            file.write(content)

    def read_last_line(self, filename) -> str:
        """
        Takes a filename containing a list of ips and returns
        the last ip address
        """
        with open(filename, "rb") as file:
            try:  # catch OSError in case of one line file
                file.seek(-2, os.SEEK_END)
                while file.read(1) != b"\n":
                    file.seek(-2, os.SEEK_CUR)
            except OSError:
                file.seek(0)
            last_line = file.readline().decode()
        return last_line
