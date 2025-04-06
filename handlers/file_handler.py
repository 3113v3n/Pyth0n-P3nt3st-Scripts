import os
from typing import Any
import pandas
from datetime import datetime
from pathlib import Path
from handlers.messages import DisplayHandler
from utils.shared import Validator
import ipaddress


class FileHandler(Validator, DisplayHandler):
    """Handle File operations"""
    FONT_NAME = "Calibri Light"
    FONT_SIZE = 12
    FONT_COLOR = "white"
    BG_COLOR = "black"

    def __init__(self) -> None:
        super().__init__()
        self.assessment_domain = ""  # one of [internals, external, mobile]
        self.working_dir = os.getcwd()
        self.output_directory = (
            # directory to save our output files
            f"{self.working_dir}/output_directory"
        )
        self.filepath = ""  # full path to a saved file
        self.files = []
        self.live_hosts_file = ""
        self.unresponsive_hosts_file = ""
        self.existing_unresponsive_ips = set()

    @classmethod
    def reset_class_states(cls):
        """Reset the states of the class"""
        cls.working_dir = os.getcwd()
        cls.output_directory = (
            # directory to save our output files
            f"{cls.working_dir}/output_directory"
        )
        cls.filepath = ""  # full path to a saved file
        cls.files = []
        cls.live_hosts_file = ""
        cls.unresponsive_hosts_file = ""

    def set_new_dir(self, new_path):
        """Universal function to update output directory"""
        base_dir = f"{self.output_directory}/{new_path}"

        # create the directory if its absent
        self.create_folder(new_path)
        return base_dir

    def update_output_directory(self, domain):
        """
        Depending on the test domain provided,
        we update the output directory for various file output
        """
        handlers = {
            "internal": lambda: self.set_new_dir("Internal"),
            "mobile": lambda: self.set_new_dir("Mobile"),
            "external": lambda: self.set_new_dir("External"),
            "password": lambda: self.set_new_dir("Password"),
            "va": lambda: self.set_new_dir("Vulnerability-Assessment")
        }
        dir_handler = handlers.get(domain)
        if dir_handler:
            return dir_handler()
        else:
            self.print_error_message(
                f"Can not create directory for invalid domain: {domain}"
            )

    def save_txt_file(self, filename, content):
        self.filepath = f"{self.output_directory}/{filename}"
        with open(f"{self.output_directory}/{filename}", "a") as file:
            file.write(f"{content}\n")

    def write_to_multiple_sheets(
            self, dataframe_objects: list, filename: str, **kwargs
    ):
        """Dataframe Object containing dataframes and their equivalent sheet names"""
        self.filepath = f"{self.output_directory}/{self.generate_unique_name(filename, extension='xlsx')}"

        # Define formats
        header_formats = {
            "font_name": self.FONT_NAME,
            "font_size": self.FONT_SIZE,
            "font_color": self.FONT_COLOR,
            "bg_color": self.BG_COLOR,
            "bold": True
        }

        cell_formats = {
            "font_name": self.FONT_NAME,
            "font_size": self.FONT_SIZE,
        }

        with pandas.ExcelWriter(self.filepath, engine="xlsxwriter") as writer:
            for dataframe in dataframe_objects:
                if not dataframe["dataframe"].empty:
                    sheetname = dataframe["sheetname"]
                    df = dataframe["dataframe"].copy()

                    url_column_name = "See Also"

                    if url_column_name in df.columns:
                        # Convert URLs to strings and add leading space
                        # to prevent hyperlink detection
                        df[url_column_name] = df[url_column_name].astype(str).apply(
                            lambda x: ' ' + x if pandas.notnull(x) else x)
                        
                    df.to_excel(writer, sheet_name=sheetname, index=False)

                    # TODO: handle URLs in See Also to prevent errors

                    workbook = writer.book
                    worksheet = writer.sheets[sheetname]

                    # format workbook headers
                    formatted_headers = workbook.add_format(header_formats)
                    # format cell
                    formatted_cell = workbook.add_format(cell_formats)

                    # Apply header format to the first row (A1:G1)
                    for col_num, value in enumerate(df.columns.values):
                        worksheet.write(0, col_num, value, formatted_headers)

                    # Apply cell format to data rows
                    worksheet.set_column('A:ZZ', 15, formatted_cell)

        # self.print_success_message(
        #     message="Analyzed Vulnerabilities have been written to :",
        #     extras=self.filepath
        # ) 
        self.print_info_message( 
            message="Analyzed Vulnerabilities have been written to :",
            file_path=self.filepath)

    def save_to_csv(self, filename, content, *args):
        """ 
        Save contents to CSV file

        :param filename: name of the file the content is going to be saved to
        :param content: content to be saved
        :param args: extra argument if necessary
        """

        filename = self.get_file_basename(filename)

        # If filename is not full path prepend output_directory
        if not os.path.isabs(filename) and not filename.startswith(self.output_directory):
            file_path = os.path.join(self.output_directory, filename)
        else:
            file_path = filename

        # TODO: Remove CSV headers
        if "unresponsive_hosts" not in filename:
            # column_name = "Live Host IP Addresses"
            self.live_hosts_file = file_path

        else:
            # column_name = "Unresponsive IP Addresses"
            self.unresponsive_hosts_file = file_path

        # Ensure content is a list (handles single value or multiple values)
        if not isinstance(content, (list, tuple)):
            content = [content]

        # Flatten nested lists if present
        flat_content = [item if not isinstance(
            item, (list, tuple))else item[0] for item in content]
        data = pandas.DataFrame(flat_content, columns=None)

        if self.file_exists(f"{file_path}"):
            existing_df = self.read_csv(f"{file_path}", ip_list=True)
            # remove duplicates by converting to set and back to dataFrame
            existing_ips = set(existing_df[0].to_list())
            new_ips = set(flat_content)
            combined_ips = existing_ips.union(new_ips)
            # updated_df = self.concat_dataframes(existing_df, data)
            updated_df = pandas.DataFrame(list(combined_ips), columns=None)
        else:
            updated_df = data

        updated_df.to_csv(f"{file_path}", header=False, index=False,
                          lineterminator='\n')  # save without header

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
        return self.files

    def display_saved_files(self, dir_to_search, **kwargs):
        """Display to the user a list of files available"""
        self.find_files(dir_to_search)

        self.files = self._get_filtered_files(**kwargs)

        if not self.files:
            return None

        # Display available files
        self._display_file_options()
        # Resume scan
        return self._handle_analysis(**kwargs)

    def _get_filtered_files(self, **kwargs) -> list:
        """Get filtered files based on user input

        :param kwargs: Keyword arguments
        :return: List of filtered files
        """
        file_collection = self._get_file_collections()

        # Apply filters based on kwargs
        if kwargs.get("scan_extension"):
            return self._filter_files_by_extension(
                file_collection,
                kwargs["scan_extension"]
            )
        elif kwargs.get("resume_scan"):
            return self._filter_unresponsive_host_files(file_collection["csv"])
        elif kwargs.get("display_applications"):
            return file_collection["applications"]
        return self.files

    def _get_file_collections(self) -> dict:
        """ Get different collections of files b type
        :Returns: Dictionary of file collections
        """

        def get_files_by_type(ext):
            """Filter files by extension type

            :param
                ext: File extension
            :Returns
                list: Files matching the extension
            """
            return list(filter(
                lambda file: self.check_filetype(
                    file["filename"],
                    ext
                ),
                self.files
            ))

        csv_files = get_files_by_type("csv")
        xlsx_files = get_files_by_type("xlsx")
        both_files = csv_files + xlsx_files
        application_files = list(filter(
            lambda file: self.check_filetype(file["filename"], "apk") or
            self.check_filetype(file["filename"], "ipa"),
            self.files
        ))
        return {
            "csv": csv_files,
            "xlsx": xlsx_files,
            "both": both_files,
            "applications": application_files
        }

    @staticmethod
    def _filter_unresponsive_host_files(csv_files) -> list[Any] | None:
        """
        Filter out CSV files only who are unresponsive

        :param csv_files: List of CSV files
        :return: List of unresponsive host files
        """
        unresponsive_file = list(filter(
            lambda file: "unresponsive_host" in file["filename"],
            csv_files
        ))
        if not unresponsive_file:
            return None
        return unresponsive_file

    def _filter_files_by_extension(self, collections, extension) -> Any | None:
        """Filter files by extension

        :param
                collections: Dictionary of file collections
                extension: Extension to filter by

        :return: List of files filtered by extension
        """
        if extension not in ["csv", "xlsx","xlx", "both"]:
            self.print_error_message(f"Invalid extension: {extension}")
            return None
        filtered_files = collections[extension]

        if not filtered_files:
            self.print_error_message("No files found")
            return None
        return filtered_files

    def _display_file_options(self):
        """Display available file options to user"""
        for index, file in enumerate(self.files, 1):
            self.print_selection_items(file, index)

    def _handle_analysis(self, **kwargs):
        if kwargs.get("scan_extension"):
            # Display files to perform VA analysis
            return self.do_analysis("files")

        elif kwargs.get("display_applications"):
            return self.do_analysis("applications")

        elif kwargs.get("resume_scan"):
            # Handle users choice
            # returns the last ip address
            return self.do_analysis()

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
                    self.print_error_message("The selected number is out of range."
                                             f" Please enter a valid number between 1 & {len(data_list)}")
            except ValueError:
                self.print_error_message(
                    "Invalid input. Please enter a number.")
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
                "Please enter the file number you would like scan first : ", self.files
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
        """Handles reading of CSV files
        Args:
            dataframe : The file to be read
        **kwargs: 
               header
               ip_list : handles file that have ips
        """
        if "header" in kwargs:
            return pandas.read_csv(dataframe, header="infer")
        # utf-16 cp1252
        if kwargs.get("ip_list"):
            return pandas.read_csv(dataframe, encoding="ISO-8859-1", header=None)
        return pandas.read_csv(dataframe, encoding="ISO-8859-1")

    @staticmethod
    def read_excel_file(file, **kwargs):
        try:
            return pandas.read_excel(
                file,
                engine="openpyxl",
                **kwargs
            )
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
            # Copy existing sheets to a writer
            for sheet_name in writer.book.sheetnames:
                df = pandas.read_excel(
                    file, sheet_name=sheet_name, engine="openpyxl")
                df.to_excel(writer, sheet_name=sheet_name, index=False)
            # Write new data frame to a new sheet
            data_frame["dataframe"].to_excel(
                writer, sheet_name=data_frame["sheetname"], index=False
            )

    def get_last_unresponsive_ip(self, unresponsive_file):
        """
        Takes a file as an input, sorts the ips available in the list in ascending order
        get the last Ip on the list to use as start_ip

        """
        self.existing_unresponsive_ips = self.load_existing_ips(
            unresponsive_file)
        ip_list = list(self.existing_unresponsive_ips)
        sorted_ips = sorted(
            ip_list, key=lambda ip: ipaddress.ip_address(ip)
        )
        total = len(self.existing_unresponsive_ips)
        self.print_info_message("Total IPs loaded ", file_path=total)
        if sorted_ips:
            last_address = sorted_ips[-1]
            self.print_info_message(
                "Resuming scan from IP address : ", file_path=last_address)
            return last_address

    def load_existing_ips(self, datafile):
        existing_ips = set()
        with open(datafile, 'r') as file:
            for line in file:
                ip = line.strip()
                if ip:
                    existing_ips.add(ip)
        return existing_ips

    @staticmethod
    def concat_dataframes(df:list):
        """Concatenate data Frames"""
        return pandas.concat(df, ignore_index=True, axis=0)

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
    def create_pd_dataframe(data: list, columns: list):
        """Create a pandas dataframe from a list of dictionaries"""
        return pandas.DataFrame(data, columns=columns)

    @staticmethod
    def read_all_lines(file):
        with open(file, "r") as file:
            return file.readlines()

    def remove_file(self, file):
        """Delete file from system"""
        try:
            file_path = Path(file)
            file_path.unlink(missing_ok=True)
        except Exception as e:
            self.print_error_message(exception_error=e)

    @staticmethod
    def generate_unique_name(file, extension="txt") -> str:
        timestamp = datetime.now().strftime("%d-%m-%Y-%H:%M:%S")
        removed_extension = Path(file).stem
        return f"{removed_extension}_{timestamp}.{extension}"

    @staticmethod
    def sort_dataframe(dataframe, order):
        return pandas.Categorical(dataframe, categories=order, ordered=True)
