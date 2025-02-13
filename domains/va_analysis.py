# trunk-ignore-all(isort)t
from handlers import FileHandler
from utils import Config, FilterVulnerabilities


class VulnerabilityAnalysis(FileHandler, Config, FilterVulnerabilities):
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
        # Update Inherited class attribute
        super().update_scanner(scanner)

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

            # Sort Vulnerabilities using Risk
            return formated_vulnerabilities.sort_values(by='Risk')

        elif self.scanner == "rapid":
          
            #print("TODO: Filter further i.e Credentialed Hosts")
            
            return self.data[self.headers[:-1]]

    def get_missing_columns(self, dataframe, filename):
        # compare the headers from our defined headers and provided dataframe

        if self.scanner == "nessus":
            self.headers = self.NESSUS_HEADERS
        elif self.scanner == "rapid":
            self.headers = self.RAPID7_HEADERS

        missing_columns = list(set(self.headers) - set(dataframe.columns))
        if missing_columns:
            raise KeyError(
                f"The following columns are missing from the "
                f"{filename} \n{missing_columns}"
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

    def analyze_scan_files(self, domain, csv_data) -> list:
        """Takes in list of csv files and returns list of vulnerabilities
        for both Nessus and Rapid7 Scanners
        """
        # update our storage path
        self.update_output_directory(domain)
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
            all_vulnerabilities = self.loop_through_files(
                file_list=self.file_list,
                start_file=self.starting_file,
                error_text=self.column_mismatch_error,
                original_datafile=original_file,
                read_csv=self.read_csv,
                get_missing_columns=self.get_missing_columns,
                concat_dataframes=self.concat_dataframes
            )

            self.data = all_vulnerabilities
        except (ValueError, KeyError) as error:
            print(error)

        return self.format_input_file()

    def filter_condition(self, filter_string: str):
        """Filter CSV file using the key word supplied
        :param: filter_string ==> String to use when filtering
        """

        return self.filter_vulnerabilities(
            self.vulnerabilities, filter_param=filter_string
        )[filter_string]

    def categorize_vulnerabilities(self) -> dict:
        """Function returns a dictionary containing tuple
        {(dataframe_name : dataframe)}
        """
        # Apply filtering dynamically
        categorized_vulnerabilities = {}
        categories = None
        if self.scanner == "nessus":
            categories = self.NESSUS_VULN_CATEGORIES
            # Special case for RCE condition
            categorized_vulnerabilities["rce"] = self.vulnerabilities[
                self.filter_condition("rce_condition")
                & ~self.filter_condition("missing_patch_condition")
                & ~self.filter_condition("unsupported_software")
            ]

        elif self.scanner == "rapid":
            categories = self.RAPID7_VULN_CATEGORIES

        categorized_vulnerabilities = {
            key: self.vulnerabilities[self.filter_condition(value)]
            for key, value in categories.items()
        }
        return categorized_vulnerabilities

    def sort_vulnerabilities(self, vulnerabilities, output_file):
        self.vulnerabilities = vulnerabilities
        filter_strings = None

        if self.scanner == "nessus":
            filter_strings = self.NESSUS_STRINGS_TO_FILTER
        elif self.scanner == "rapid":
            filter_strings = self.RAPID7_STRINGS_TO_FILTER

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
                f"{self.get_filename_without_extension(
                    output_file)}_Unfiltered",
                unfiltered=True,
            )
        # write to file if data is present
        if len(found_vulnerabilities) != 0:
            self.write_to_multiple_sheets(
                found_vulnerabilities,
                output_file,
            )
