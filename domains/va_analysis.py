# trunk-ignore-all(isort)t
from handlers import FileHandler
from utils import Config


class VulnerabilityAnalysis(FileHandler, Config):
    """Class that handles Vulnerability analysis tasks"""

    def __init__(self) -> None:
        # File manager class that is responsible for file operations
        super().__init__()
        self.data = []
        # list of hosts that passed credential check
        self.credentialed_hosts = []
        # CSV headers used for analysis
        self.headers = None  # config.nessus_headers
        # columns to showcase on our final excel
        self.selected_columns = []
        # contains constants to be used across the program
        # Scanner_type
        self.scanner = "nessus"
        self.vulnerabilities = []
        # file_attributes
        self.file_type = ""
        self.file_list = []
        self.starting_index = 0
        self.starting_file = ""

    def set_scanner(self, scanner: str):
        self.scanner = scanner

    def set_file_type(self, file_type: str):
        self.file_type = file_type

    def format_input_file(self) -> list:
        # lists of hosts that passed credential check
        # filter hosts with credential check successful
        if self.scanner == "nessus":

            credentialed_hosts = self.data[
                (self.csv_filter_operations(self.data, "Plugin Output", "notnull"))
                & (
                    self.csv_filter_operations(
                        self.data,
                        "Plugin Output",
                        "contains",
                        contains_key="Credentialed checks : yes",
                    )
                )
                ]["Host"].tolist()
            self.credentialed_hosts = credentialed_hosts

            selected_columns = self.data[
                self.csv_filter_operations(
                    self.data, "Host", "in", in_key=self.credentialed_hosts
                )
            ][
                self.headers[:-1]  # ignore the last item in our headers list
            ]

            # Return only [ Critical | High | Medium ] Risks and notnull values
            formated_vulnerabilities = selected_columns[
                (self.csv_filter_operations(selected_columns, "Risk", "notnull"))
                & (selected_columns["Risk"] != "Low")
                ].reset_index(drop=True)
            print(f"\nCredentialed Hosts: \n{self.credentialed_hosts}")

            return formated_vulnerabilities

        elif self.scanner == "rapid":
            print("Rapid Vulnerability Analysis")
            return self.data

    def get_missing_columns(self, dataframe, filename):
        # compare the headers from our defined headers and provided dataframe

        if self.scanner == "nessus":
            self.headers = self.nessus_headers
        elif self.scanner == "rapid":
            self.headers = self.rapid7_headers

        missing_columns = list(set(self.headers) - set(dataframe.columns))
        if missing_columns:
            raise KeyError(
                f"The following columns are missing from the {filename} \n{missing_columns}"
            )

    def set_scan_attributes(self, attributes: tuple) -> None:
        """
        :param :( [list_of_csv_files], index_of_selected_file )
        sets file_list ==> list of csv_files
             start_index == 0 ==> index of selected csv
             starting_file ==> starting file name
        """
        self.file_list = attributes[0]
        self.starting_index = attributes[1]
        self.starting_file = self.file_list[self.starting_index]["full_path"]

    def analyze_scan_files(self, csv_data) -> list:
        """Takes in list of csv files and returns list of vulnerabilities
        for both Nessus and Rapid7 Scanners
        """
        self.set_scan_attributes(csv_data)

        try:
            # Read the first file as baseline
            filename = self.file_list[self.starting_index]["filename"]
            original_file = self.read_csv(self.starting_file)

            # Check if baseline file is empty
            if original_file.empty:
                raise ValueError(f"Baseline file {filename} is empty")

            # Check missing columns in base file
            self.get_missing_columns(original_file, filename)
            all_vulnerabilities = original_file

            # Iterate through the list of files and append data from each file
            for file in self.file_list:
                if file["full_path"] != self.starting_file:
                    # Read CSV file without headers
                    new_data = self.read_csv(file["full_path"], header=None)

                    # Check if new data is empty
                    if new_data.empty:
                        print(f"Skipping empty file : {file['filename']}")
                        continue

                    # Ensure columns match
                    if original_file.shape[1] != new_data.shape[1]:
                        print(
                            f"New file {file['filename']} has {len(new_data.columns)} columns "
                        )
                        raise ValueError(self.column_mismatch_error)

                    # Check if other files have missing columns
                    self.get_missing_columns(new_data, file["filename"])
                    # Append new data to the original data
                    all_vulnerabilities = self.concat_dataframes(
                        all_vulnerabilities, new_data
                    )

            self.data = all_vulnerabilities
        except (ValueError, KeyError) as error:
            print(error)

        return self.format_input_file()

    def sort_vulnerabilities(self, vulnerabilities, output_file):
        if self.scanner == "nessus":
            self.sort_nessus_vulnerabilities(vulnerabilities, output_file)
        elif self.scanner == "rapid7":
            self.sort_rapid7_vulnerabilities(vulnerabilities, output_file)

    def filter_condition(self, filter_string: str):
        """Filter CSV file using the key word supplied
        :param: filter_string ==> String to use when filtering
        """

        return self.filter_conditions(
            self.vulnerabilities, regex_word=self.regex_word, filter_param=filter_string
        )[filter_string]

    def categorize_vulnerabilities(self) -> dict:
        """Function returns a dictionary containing tuple
        {(dataframe_name : dataframe)}
        """
        # Apply filtering dynamically
        categorized_vulnerabilities = {}
        categories = None
        if self.scanner == "nessus":
            categories = self.nessus_vuln_categories
            # Special case for RCE condition
            categorized_vulnerabilities["rce"] = self.vulnerabilities[
                self.filter_condition("rce_condition")
                & ~self.filter_condition("missing_patch_condition")
                & ~self.filter_condition("unsupported_software")
                ]

        elif self.scanner == "rapid":
            categories = self.rapid7_vuln_categories

        categorized_vulnerabilities = {
            key: self.vulnerabilities[self.filter_condition(value)]
            for key, value in categories.items()
        }
        return categorized_vulnerabilities

    def sort_nessus_vulnerabilities(self, vulnerabilities, output_file):
        self.vulnerabilities = vulnerabilities
        filter_strings = None

        if self.scanner == "nessus":
            filter_strings = self.nessus_strings_to_filter
        elif self.scanner == "rapid":
            filter_strings = self.rapid7_strings_to_filter

        # Show remaining data after filtering
        # Start loop from the second value and append results
        # to combined filter

        combined_filter = ~self.filter_condition(filter_strings[0])
        for condition in filter_strings[1:]:
            combined_filter &= ~self.filter_condition(condition)

        unfiltered = self.vulnerabilities[combined_filter]

        # returns tuple containing key, value pair of dataframe
        # identifier and dataframe

        issues = self.categorize_vulnerabilities()
        found_vulnerabilities = []
        for issue in issues.items():
            found_vulnerabilities.append(
                {"dataframe": issue[1], "sheetname": f"{issue[0]}"}
            )

        self.save_vulns_to_files(
            unfiltered_data=unfiltered,
            found_vulnerabilities=found_vulnerabilities,
            output_file=output_file,
        )

    def save_vulns_to_files(self, unfiltered_data, found_vulnerabilities, output_file):
        """Handles Saving data to File"""
        unfiltered_vulnerabilities = [
            {"dataframe": unfiltered_data, "sheetname": "Unfiltered"}
        ]
        if not unfiltered_data.empty:
            """
            For the unfiltered vulnerabilities, append 'Unfiltered'
            to the user provided filename for easy identification
            """
            self.write_to_multiple_sheets(
                unfiltered_vulnerabilities,
                f"{self.get_filename_without_extension(output_file)}_Unfiltered",
                unfiltered=True,
            )
        # write to file if data is present
        if len(found_vulnerabilities) != 0:
            self.write_to_multiple_sheets(
                found_vulnerabilities,
                output_file,
            )

    def sort_rapid7_vulnerabilities(self, vulnerabilities, output_file):
        conditions = self.filter_conditions(
            vulnerabilities, regex_word=self.regex_word, filter_param=""
        )
        unfiltered_vulns = []
        found_vulnerabilities = []
        print(f"{conditions}\n{unfiltered_vulns}\n{found_vulnerabilities}\n{output_file}")

    @staticmethod
    def percentage_null_fields(dataframe):
        # determine percentage accuracy of the data by showing null fields
        for i in dataframe.columns:
            null_rate = dataframe[i].isna().sum() / len(dataframe) * 100
            if null_rate > 0:
                print(f"{i} null rate: {null_rate:.2f}%")

    @staticmethod
    def csv_filter_operations(dataframe, filter_option, operation, **kwargs):
        # Function to combine all the major CSV filters into one for code clarity
        match operation:
            case "notnull":
                return dataframe[filter_option].notna()
            case "contains":
                if "contains_key" in kwargs:
                    # check for any key value pair passed as an  extra argument and uses it as a filter
                    return dataframe[filter_option].str.contains(kwargs["contains_key"])
            case "in":
                if "in_key" in kwargs:
                    return dataframe[filter_option].isin(kwargs["in_key"])
            case _:
                raise ValueError(f"Invalid filter option: {filter_option}")

    @staticmethod
    def regex_word(search_term, **kwargs):
        if "is_extra" in kwargs:
            return rf'\b{search_term}\b(?!.*\b{kwargs["second_term"]}\b)'
        return rf"\b{search_term}\b"
