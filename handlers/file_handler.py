import os
import pandas
from datetime import datetime
from pathlib import Path
from utils.shared import InputValidators


def read_csv(dataframe, **kwargs):
    if "header" in kwargs:
        return pandas.read_csv(dataframe, header="infer")
    return pandas.read_csv(dataframe)


def read_excel_file(file):
    xls = pandas.ExcelFile(file)
    return pandas.read_excel(xls)


def get_filename_without_extension(filepath):
    # Get the filename with extension
    filename_with_ext = os.path.basename(filepath)
    # Split the filename and extension
    filename_without_ext, _ = os.path.splitext(filename_with_ext)
    return filename_without_ext


def get_file_extension(filename):
    # Split the filename into root and extension
    root, ext = os.path.splitext(filename)
    # Return the extension, excluding the dot
    return ext.lstrip(".")


def append_to_sheets(data_frame: object, file: str):
    """Appends data to existing Workbook"""
    with pandas.ExcelWriter(
        file, engine="openpyxl", mode="a", if_sheet_exists="overlay"
    ) as writer:
        # Copy existing sheets to writer
        for sheet_name in writer.book.sheetnames:
            df = pandas.read_excel(file, sheet_name=sheet_name, engine="openpyxl")
            df.to_excel(writer, sheet_name=sheet_name, index=False)
        # Write new data frame to new sheet
        data_frame["dataframe"].to_excel(
            writer, sheet_name=data_frame["sheetname"], index=False
        )


def concat_dataframes(existing, newdata):
    """Concatenate two data Frames"""
    return pandas.concat([existing, newdata], ignore_index=True, axis=0)


def get_file_basename(full_file_path):
    return os.path.basename(full_file_path)


def append_to_txt(filename, content):
    """Update existing file"""
    with open(f"{filename}", "a") as file:
        file.write(f"{content}\n")


def read_last_line(filename) -> str:
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


def read_all_lines(file):
    with open(file, "r") as file:
        return file.readlines()


def generate_unique_name(file, extension) -> str:
    timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
    removed_extension = Path(file).stem
    return f"{removed_extension}_{timestamp}.{extension}"


class FileHandler:
    """Handle File operations"""

    def __init__(self, colors, validator: InputValidators) -> None:
        self.assessment_domain = ""  # one of [internal,external,mobile]
        self.working_dir = os.getcwd()
        self.output_directory = (
            f"{self.working_dir}/output_directory"  # directory to save our output files
        )
        self.filepath = ""  # full path to saved file
        self.files = []
        self.colors = colors
        self.validator = validator
        self.mobile_dir = "Mobile"
        self.external_dir = "External"
        self.internal_dir = "Internal"
        self.va_dir = "Vulnerability_Assessment"

    def update_output_directory(self, domain):
        """
        Depending on the test domain provided
        we update the output directory for various file output
        """
        match domain:
            case "mobile":
                self.output_directory = f"{self.output_directory}/{self.mobile_dir}"
                # create folder if not existent
                self.create_folder(self.mobile_dir)
                return self.output_directory
            case "internal":
                self.output_directory = f"{self.output_directory}/{self.internal_dir}"
                # create folder if not existent
                self.create_folder(self.internal_dir)
                return self.output_directory
            case "external":
                self.output_directory = f"{self.output_directory}/{self.external_dir}"
                # create folder if not existent
                self.create_folder(self.external_dir)
                return self.output_directory
            case "va":
                self.output_directory = f"{self.output_directory}/{self.va_dir}"
                # create folder if not existent
                self.create_folder(self.va_dir)
                return self.output_directory
            case _:
                return

    def save_txt_file(self, filename, content):
        self.filepath = f"{self.output_directory}/{filename}"
        with open(f"{self.output_directory}/{filename}", "a") as file:
            file.write(f"{content}\n")

    def write_to_multiple_sheets(self, dataframe_objects: list, filename: str):
        """Dataframe Object containing dataframes and their equivalent sheet names"""
        self.filepath = f"{self.output_directory}/{generate_unique_name(filename, extension='xlsx')}"
        with pandas.ExcelWriter(self.filepath) as writer:
            for dataframe in dataframe_objects:
                if not dataframe["dataframe"].empty:
                    dataframe["dataframe"].to_excel(
                        writer, sheet_name=dataframe["sheetname"], index=False
                    )
        print(
            f"Data has been written to :\n{self.colors.OKGREEN}{self.filepath}{self.colors.ENDC}\n"
        )

    def save_to_csv(self, filename, content, mode):
        if mode == "scan":
            self.filepath = f"{self.output_directory}/{filename}"
        else:
            self.filepath = filename

        file_header = ""
        if filename != "unresponsive_hosts":
            file_header += "Live Host IP Addresses"
        else:
            file_header += "Unresponsive IP Addresses"
            # print(f"Resuming unresponsive scan from :{self.filepath}\nFilename: {filename}")
            self.filepath = f"{self.output_directory}/unresponsive_hosts.txt"

        data = pandas.DataFrame({file_header: [content]})

        if self.validator.file_exists(f"{self.filepath}"):
            existing_df = read_csv(f"{self.filepath}")

            updated_df = concat_dataframes(existing_df, data)
        else:
            updated_df = data

        updated_df.to_csv(f"{self.filepath}", index=False)

    def create_folder(self, folder_name, search_path="./output_directory"):

        self.output_directory = f"{search_path}/{folder_name}"

        if not self.validator.check_subdirectory_exists(
            folder_name, search_path=search_path
        ):
            folder_path = self.output_directory
            os.makedirs(folder_path)

    def find_files(self, search_path):
        """
        Searches for a file in the given directory and its subdirectories.

        :param search_path: Directory to start the search from.
        :return: Full path of the files if found, None otherwise.
        """

        for root, _, files in os.walk(search_path):

            for file in files:
                file_object = {"filename": file, "full_path": os.path.join(root, file)}
                self.files.append(file_object)

    def display_saved_files(self, dir_to_search, **kwargs):
        """Display to the user a list of files available
        and returns the last ip present in that file"""
        self.find_files(dir_to_search)

        csv_files = [
            file
            for file in self.files
            if self.validator.check_filetype(file["filename"], "csv")
        ]
        app_files = [
            file
            for file in self.files
            if self.validator.check_filetype(file["filename"], "apk")
            or self.validator.check_filetype(file["filename"], "ipa")
        ]
        # filter out CSV files only
        if "display_csv" in kwargs:
            self.files = csv_files

        # allow user to view only apks and ios
        elif "display_applications" in kwargs:
            self.files = app_files

        if len(self.files) != 0:
            display_strs = []  # list to collect all display strings

            for index in range(len(self.files)):
                # Prepare the display string for each file
                filename = f" {self.colors.BOLD}{self.colors.WARNING}{self.files[index]['filename']}{self.colors.ENDC}"
                display_str = f"Enter [{self.colors.OKGREEN}{self.colors.BOLD}{index}{self.colors.ENDC}] to select{filename} "
                display_strs.append(display_str)

            # print all collected strings
            for display_str in display_strs:
                print(display_str)

            # Resume scan
            if "display_csv" in kwargs:
                # Display files to perform VA analysis
                return self.select_analyze_file()

            elif "display_applications" in kwargs:
                return self.analyze_applications()

            else:
                # Handle users choice
                return self.get_last_ip()

        else:
            return None

    def universal_display_loop(self, input_str):
        while True:
            # Error handling
            try:
                selected_file = int(input(f"\n{input_str}"))
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
        return selected_file

    def select_analyze_file(self):
        """
        During VA analysis, display all CSV files to analyze and select the one to start from
        return Tuple containing the list of CSV files and the index to start scan
        """
        selected = self.universal_display_loop(
            "Please enter the file number you would like scan first : "
        )
        return self.files, selected

    def analyze_applications(self):
        selected_apk = self.universal_display_loop("Select the application to scan ")
        return self.files[selected_apk]

    def get_last_ip(self):
        """Returns the IP address from a file input"""
        selected_file = self.universal_display_loop(
            "Please enter the file number displayed above: "
        )

        self.filepath = self.files[selected_file]["full_path"]
        starting_ip = read_last_line(self.filepath)
        return starting_ip
