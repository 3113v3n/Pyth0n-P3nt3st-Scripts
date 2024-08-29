import os
from datetime import datetime
from pathlib import Path
from utils.shared import InputValidators

# from pprint import pprint
import pandas


class FileHandler:
    """Handle File operations"""

    def __init__(self, colors, validator: InputValidators) -> None:
        self.test_domain = ""  # one of [internal,external,mobile]
        self.working_dir = os.getcwd()
        self.output_directory = (
            f"{self.working_dir}/output_directory"  # directory to save our output files
        )
        self.full_file_path = ""  # full path to saved file
        self.files = []
        self.colors = colors
        self.validator = validator

    def update_output_directory(self, domain):
        """
        Depending on the test domain provided
        we update the output directory for various file output
        """
        match domain:
            case "mobile":
                self.output_directory = f"{self.output_directory}/mobile"
                self.create_folder("mobile")
                return self.output_directory
            case "internal":
                self.output_directory = f"{self.output_directory}/internal"
                self.create_folder("internal")
                return self.output_directory
            case "external":
                self.output_directory = f"{self.output_directory}/external"
                self.create_folder("external")
                return self.output_directory
            case "va":
                self.output_directory = (
                    f"{self.output_directory}/vulnerability-assessment"
                )
                self.create_folder("vulnerability-assessment")
                return self.output_directory
            case _:
                return

    def save_txt_file(self, filename, content):
        self.full_file_path = f"{self.output_directory}/{filename}"
        with open(f"{self.output_directory}/{filename}", "a") as file:
            file.write(f"{content}\n")

    def read_csv(self, dataframe):
        return pandas.read_csv(dataframe)

    def read_excel_file(self, file):
        xls = pandas.ExcelFile(file)
        return pandas.read_excel(xls)

    def write_to_multiple_sheets(self, data_frame_object, filename):
        """Dataframe Object containing dataframes and their equivalent sheet names"""
        filepath = f"{self.output_directory}/{self.generate_unique_name(filename,extension='xlsx')}"
        with pandas.ExcelWriter(filepath) as writer:
            for dataframe in data_frame_object:
                if not dataframe["dataframe"].empty:
                    dataframe["dataframe"].to_excel(
                        writer, sheet_name=dataframe["sheetname"], index=False
                    )
        print(
            f"Data has been written to \n{self.colors.OKGREEN}{filepath}{self.colors.ENDC}"
        )

    def save_to_csv(self, filename, content, mode):
        if mode == "scan":
            self.full_file_path = f"{self.output_directory}/{filename}"
        else:
            self.full_file_path = filename

        data = pandas.DataFrame({"Live IP Addresses": [content]})

        if self.validator.file_exists(f"{self.full_file_path}"):
            existing_df = self.read_csv(f"{self.full_file_path}")

            updated_df = pandas.concat([existing_df, data], ignore_index=True)
        else:
            updated_df = data

        updated_df.to_csv(f"{self.full_file_path}", index=False)

    def append_to_txt(self, filename, content):
        """Update existing file"""
        with open(f"{filename}", "a") as file:
            file.write(f"{content}\n")

    def create_folder(self, folder_name):

        if not self.validator.directory_exists(
            folder_name, search_path="./output_directory"
        ):
            # os.getcwd()
            folder_path = self.output_directory
            os.makedirs(folder_path)
            print(f"Folder '{folder_name}' not found. Created at: {folder_path}")

    def find_files(self):
        """
        Searches for a file in the given directory and its subdirectories.

        :param search_path: Directory to start the search from.
        :return: Full path of the files if found, None otherwise.
        """

        for root, dirs, files in os.walk(f"{self.output_directory}"):

            for file in files:
                file_object = {"filename": "", "full_path": ""}
                file_object["filename"] = file
                file_object["full_path"] = os.path.join(root, file)
                self.files.append(file_object)

        # return self.files

    def display_saved_files(self) -> str:
        """Display to the user a list of files available
        and returns the last ip present in that file"""
        self.find_files()

        if len(self.files) != 0:
            for index in range(len(self.files)):
                print(
                    f"Enter [{self.colors.OKGREEN}{self.colors.BOLD}{index}{self.colors.ENDC}] to select  {self.colors.BOLD}{self.colors.WARNING}{self.files[index]['filename']}{self.colors.ENDC}"
                )
                # prompt user for filename from the displayed list and use that to get the full path
            return self.get_last_ip()
        else:
            return None

    def get_last_ip(self):
        """Returns the IP address from a file input"""
        while True:
            # Error handling
            try:
                selected_file = int(
                    input("\nPlease enter the file number displayed above: ")
                )
                if 0 <= selected_file < len(self.files):
                    break
                else:
                    print(
                        f"{self.colors.FAIL}[!]The file number is out of range. Please enter a valid number.{self.colors.ENDC}"
                    )
            except ValueError:
                print(
                    f"{self.colors.FAIL}[!!] Invalid input. Please enter a number.{self.colors.ENDC}"
                )

        self.full_file_path = self.files[selected_file]["full_path"]
        starting_ip = self.read_last_line(self.full_file_path)
        return starting_ip

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

    def read_all_lines(self, file):
        with open(file, "r") as file:
            return file.readlines()

    def generate_unique_name(self, file, extension) -> str:
        timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        removed_extension = Path(file).stem
        return f"{removed_extension}_{timestamp}.{extension}"
