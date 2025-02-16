import os
import pandas
from datetime import datetime
from pathlib import Path
from utils.shared import Validator, Bcolors
import ipaddress


class FileHandler(Validator, Bcolors):
    """Handle File operations"""

    def __init__(self) -> None:
        super().__init__()
        self.assessment_domain = ""  # one of [internal,external,mobile]
        self.working_dir = os.getcwd()
        self.output_directory = (
            # directory to save our output files
            f"{self.working_dir}/output_directory"
        )
        self.filepath = ""  # full path to saved file
        self.files = []
        self.mobile_dir = "Mobile"
        self.external_dir = "External"
        self.internal_dir = "Internal"
        self.va_dir = "Vulnerability_Assessment"
        self.live_hosts_file = ""
        self.unresponsive_hosts_file = ""

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

    def write_to_multiple_sheets(
            self, dataframe_objects: list, filename: str, **kwargs
    ):
        """Dataframe Object containing dataframes and their equivalent sheet names"""
        self.filepath = f"{self.output_directory}/{self.generate_unique_name(filename, extension='xlsx')}"
        with pandas.ExcelWriter(self.filepath) as writer:
            for dataframe in dataframe_objects:
                if not dataframe["dataframe"].empty:
                    dataframe["dataframe"].to_excel(
                        writer, sheet_name=dataframe["sheetname"], index=False
                    )
        if "unfiltered" in kwargs:
            text = (
                f"\n\nUnfiltered vulnerabilities have been written to :"
                f"\n{self.OKCYAN}{self.filepath}{self.ENDC}\n"
            )
        else:
            text = (
                f"Filtered vulnerabilities have been written to :"
                f"\n{self.OKGREEN}{self.filepath}{self.ENDC}\n"
            )
        print(text)

    def save_to_csv(self, filename, content):
        filename = self.get_file_basename(filename)

        # If filename is not full path prepend output_directory
        if not os.path.isabs(filename) and not filename.startswith(self.output_directory):
            file_path = os.path.join(self.output_directory, filename)
        else:
            file_path = filename

        # TODO: Remove CSV headers
        if "unresponsive_hosts" not in filename:
            file_header = "Live Host IP Addresses"
            self.live_hosts_file = file_path

        else:
            file_header = "Unresponsive IP Addresses"
            self.unresponsive_hosts_file = file_path

        # Live Hosts : [Ip addresses]
        data = pandas.DataFrame({file_header: [content]})

        if self.file_exists(f"{file_path}"):
            existing_df = self.read_csv(f"{file_path}")
            updated_df = self.concat_dataframes(existing_df, data)
        else:
            updated_df = data

        updated_df.to_csv(f"{file_path}", index=False)

    def get_file_paths(self) -> dict:
        """Return stored file paths for live and unresponsive hosts"""
        return {
            "live_hosts": self.live_hosts_file,
            "unresponsive_hosts": self.unresponsive_hosts_file,
        }

    def create_folder(self, folder_name, search_path="./output_directory"):

        self.output_directory = f"{search_path}/{folder_name}"

        if not self.check_subdirectory_exists(
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
                file_object = {"filename": file,
                               "full_path": os.path.join(root, file)}
                self.files.append(file_object)

    def display_saved_files(self, dir_to_search, **kwargs):
        """Display to the user a list of files available
        and returns the last ip present in that file"""
        self.find_files(dir_to_search)

        csv_files = [
            file
            for file in self.files
            if self.check_filetype(file["filename"], "csv")
        ]
        xlsx_files = [file
                      for file in self.files
                      if self.check_filetype(file["filename"], "xlsx")]
        both_files = csv_files + xlsx_files
        app_files = [
            file
            for file in self.files
            if self.check_filetype(file["filename"], "apk")
            or self.check_filetype(file["filename"], "ipa")
        ]

        # Only display files containing unresponsive hosts
        unresponsive_host_files = [
            file for file in csv_files if "unresponsive_host" in file["filename"]
        ]
        # filter out CSV files only
        if (
                "scan_extension" in kwargs
        ):  # any(key in kwargs for key in ("display_csv", "resume_scan")):
            # Show files selected by user
            if kwargs['scan_extension'] == "csv":
                self.files = csv_files
            elif kwargs['scan_extension'] == "xlsx":
                self.files = xlsx_files
            elif kwargs['scan_extension'] == "both":
                self.files = both_files

        elif "resume_scan" in kwargs:
            self.files = unresponsive_host_files

        # allow user to view only apks and ios
        elif "display_applications" in kwargs:
            self.files = app_files

        if len(self.files) != 0:
            display_strs = []  # list to collect all display strings

            for index in range(len(self.files)):
                # Prepare the display string for each file
                filename = f" {self.BOLD}{self.WARNING}{self.files[index]['filename']}{self.ENDC}"
                display_str = (
                    f"Enter [{self.OKGREEN}{self.BOLD}{index + 1}{self.ENDC}] to select"
                    f"{filename}"
                )
                display_strs.append(display_str)

            # print all collected strings
            for display_str in display_strs:
                print(display_str)

            # Resume scan
            if "scan_extension" in kwargs:
                # Display files to perform VA analysis
                return self.do_analysis("files")

            elif "display_applications" in kwargs:
                return self.do_analysis("applications")

            elif "resume_scan" in kwargs:
                # Handle users choice
                # returns the last ip address
                return self.do_analysis()

        else:
            return None

    def index_out_of_range_display(self, input_str, data_list) -> int:
        """Takes in an input string and a data list and returns the index of the
        selected item in the data list.
        :param input_str: Input string to be displayed to the user
        :param data_list: list from which data will be displayed
        """
        while True:
            # Error handling
            try:
                selected_value = int(input(f"\n{input_str}").strip())
                if (
                        0 < selected_value < len(data_list) + 1
                ):  # display numbers are value of index + 1

                    break
                else:
                    print(
                        f"{self.FAIL}\n[!]The selected number is out of range."
                        f" Please enter a valid number between 1 & {len(data_list)}{self.ENDC}."
                    )
            except ValueError:
                print(
                    f"{self.FAIL}[!!] Invalid input. Please enter a number.{self.ENDC}"
                )
                # return the index of selected item
        return selected_value - 1

    def do_analysis(self, to_analyze="") -> tuple | str:
        print(f"\n{self.OKBLUE}Analyzing {to_analyze}...{self.ENDC}")
        if to_analyze == "files":
            """
            During VA analysis, display all CSV files to analyze and select the one to start from
            return Tuple containing the list of CSV files and the index to start scan
            """
            selected_file = self.index_out_of_range_display(
                "Please enter the file number you would like scan first :", self.files
            )
            return self.files, selected_file
        elif to_analyze == "applications":
            """
            Display all applications to analyze and select the one to start from
            """
            selected_app = self.index_out_of_range_display(
                "Select the application to scan ", self.files
            )
            return self.files[selected_app]
        else:
            """Returns the IP address from a file input"""
            selected_file = self.index_out_of_range_display(
                "Please enter the file number displayed above: ", self.files
            )

            self.filepath = self.files[selected_file]["full_path"]
            starting_ip = self.get_last_unresponsive_ip(
                self.filepath
            )  # read_last_line(self.filepath)
            return starting_ip

    @staticmethod
    def read_csv(dataframe, **kwargs):
        if "header" in kwargs:
            return pandas.read_csv(dataframe, header="infer")
        # utf-16 cp1252
        return pandas.read_csv(dataframe, encoding="ISO-8859-1")

    @staticmethod
    def read_excel_file(file, **kwargs):
        try:
            return pandas.read_excel(file,
                                     engine="openpyxl",

                                     **kwargs)
        except Exception as e:
            print(f"Error reading excel file: {e}")
            raise

    @staticmethod
    def get_file_extension(filename):
        # Split the filename into root and extension
        root, ext = os.path.splitext(filename)
        # Return the extension, excluding the dot
        return ext.lstrip(".")

    @staticmethod
    def append_to_sheets(data_frame: object, file: str):
        """Appends data to existing Workbook"""
        with pandas.ExcelWriter(
                file, engine="openpyxl", mode="a", if_sheet_exists="overlay"
        ) as writer:
            # Copy existing sheets to writer
            for sheet_name in writer.book.sheetnames:
                df = pandas.read_excel(
                    file, sheet_name=sheet_name, engine="openpyxl")
                df.to_excel(writer, sheet_name=sheet_name, index=False)
            # Write new data frame to new sheet
            data_frame["dataframe"].to_excel(
                writer, sheet_name=data_frame["sheetname"], index=False
            )

    def get_last_unresponsive_ip(self, unresponsive_file):
        """
        Takes file as an input, sorts the ips available in the list in ascending order
        get the last Ip on the list to use as start_ip
        """
        try:
            data_frame = self.read_csv(unresponsive_file)

            if data_frame.empty:
                return None

            # Extract Ips from the first column
            ip_list = data_frame.iloc[:, 0].dropna().tolist()

            # Convert to IPAddress objects for correct numerical sorting
            sorted_ips = sorted(
                ip_list, key=lambda ip: ipaddress.ip_address(ip))

            last_address = sorted_ips[-1]
            return last_address

        except FileNotFoundError:
            print("No previous unresponsive host file found")

    @staticmethod
    def concat_dataframes(existing, newdata):
        """Concatenate two data Frames"""
        return pandas.concat([existing, newdata], ignore_index=True, axis=0)

    @staticmethod
    def get_file_basename(full_file_path):
        return os.path.basename(full_file_path)

    @staticmethod
    def append_to_txt(filename, content):
        """Update existing file"""
        with open(f"{filename}", "a") as file:
            file.write(f"{content}\n")

    @staticmethod
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
    
    @staticmethod
    def create_pd_dataframe(data:list, columns:list):
        """Create a pandas dataframe from a list of dictionaries"""
        return pandas.DataFrame(data, columns=columns)
    
    @staticmethod
    def read_all_lines(file):
        with open(file, "r") as file:
            return file.readlines()

    @staticmethod
    def generate_unique_name(file, extension) -> str:
        timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        removed_extension = Path(file).stem
        return f"{removed_extension}_{timestamp}.{extension}"
