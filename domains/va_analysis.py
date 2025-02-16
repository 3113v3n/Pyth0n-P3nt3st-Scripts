from typing import List, Dict, Optional
from handlers import FileHandler
from utils import Config, FilterVulnerabilities
from pprint import pprint


class VulnerabilityAnalysis(FileHandler, Config, FilterVulnerabilities):
    """Class that handles Vulnerability analysis tasks"""

    def __init__(self) -> None:
        # File manager class that is responsible for file operations
        super().__init__()
        self.data = None
        # list of hosts that passed credential check
        self.credentialed_hosts: List[str] = []
        # CSV headers used for analysis
        self.headers: Optional[List[str]] = None  # config.nessus_headers
        # columns to showcase on our final excel
        self.selected_columns: List[str] = []
        # contains constants to be used across the program
        # Scanner_type
        self.scanner: str = "nessus"
        self.vulnerabilities: List[Dict] = []
        # file_attributes
        self.file_type: str = ""
        self.file_list: List[Dict] = []
        self.starting_index: int = 0
        self.starting_file: str = ""

    def set_scanner(self, scanner: str):
        """
        Set the scanner type and update related configurations

        Args:
            scanner: Type of scanner ('nessus' or 'rapid')
        """
        self.scanner = scanner
        # Update Inherited class attribute
        super().update_scanner(scanner)
        # Set headers based on scanner type
        self.headers = self.NESSUS_HEADERS if scanner == "nessus" else self.RAPID7_HEADERS

    def set_file_type(self, file_type: str):
        self.file_type = file_type

    def format_input_file(self) -> list:
        """
        Formats the input data based on scanner type and filtering criteria

        Returns:
            Formatted DataFrame with filtered vulnerabilities
        """
        if self.data is None or self.headers is None:
            raise ValueError("Data or headers not set")

        if self.scanner == "nessus":
            return self.format_nessus_data()
        elif self.scanner == "rapid":
            return self.format_rapid7_data()
        else:
            raise ValueError(f"Unsupported scanner: {self.scanner}")

    def format_nessus_data(self):
        """
        Formats Nessus data based on credentialed hosts and selected columns

        Returns:
            Formatted DataFrame with filtered vulnerabilities
        """
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

    def format_rapid7_data(self):
        """
        Formats Rapid data based on selected columns

        Returns:
            Formatted DataFrame with filtered vulnerabilities
        """
        # print("TODO: Filter further i.e Credentialed Hosts")
        pprint(f"Headers ==> {self.headers}")
        return self.data[self.headers[:-1]]

    def get_missing_columns(self, dataframe, filename):
        # compare the headers from our defined headers and provided dataframe

        missing_columns = list(set(self.headers) - set(dataframe.columns))
        if missing_columns:
            raise KeyError(
                f"The following columns are missing from the "
                f"{filename} : {missing_columns}"
            )

    def set_scan_attributes(self, attributes: tuple) -> None:
        """
        :param :( [list_of_files], index_of_selected_file )
        sets file_list ==> list of scanned_files [CSV|XLSX]
             start_index == 0 ==> index of selected file
             starting_file ==> starting file name
        """
        self.file_list = attributes[0]
        self.starting_index = attributes[1]
        self.starting_file = self.file_list[self.starting_index]["full_path"]

    def analyze_scan_files(self, domain: str, csv_data: tuple) -> list:
        """
        Analyzes vulnerability scan files and returns formatted results

        Args:
            domain: The assessment domain (e.g., 'internal', 'external')
            scan_data: Tuple containing file information

        Returns:
            Formatted DataFrame of vulnerabilities or None if processing fails
        """

        try:
            # update our storage path
            self.update_output_directory(domain)
            self.set_scan_attributes(csv_data)

            # Check if baseline file is empty
            original_file = self._process_initial_file()
            if original_file is None:
                return None

            # Process remaining files
            all_vulnerabilities = self.loop_through_files(
                file_list=self.file_list,
                start_file=self.starting_file,
                error_text=self.column_mismatch_error,
                original_datafile=original_file,
                read_csv=self.read_csv,
                get_missing_columns=self.get_missing_columns,
                concat_dataframes=self.concat_dataframes,
                read_xlsx=self.read_excel_file,
                get_file_extension=self.get_file_extension,
            )
            if all_vulnerabilities is None:
                return None

            self.data = all_vulnerabilities
            return self.format_input_file()

        except Exception as error:
            print(
                f"{self.FAIL}[!] Error analyzing scan files: {str(error)}{self.ENDC}")
            return None

    def _process_initial_file(self):
        """Process the initial file and handle errors

        Returns:
            DataFrame from initial file or None if processing fails
        """
        try:
            filename = self.file_list[self.starting_index]["filename"]
            file_extension = self.get_file_extension(self.starting_file)

            if file_extension.lower() == "csv":
                original_file = self.read_csv(self.starting_file)
            elif file_extension.lower() in ["xlsx", "xls"]:
                original_file = self.read_excel_file(
                    self.starting_file, header=None)
            else:
                raise ValueError(
                    f"Unsupported file extension: {file_extension}")

            self.get_missing_columns(original_file, filename)
            return original_file

        except Exception as error:
            print(
                f"{self.FAIL}[!] Error processing initial file: {str(error)}{self.ENDC}")
            return None

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
        filter_strings = (self.NESSUS_STRINGS_TO_FILTER if self.scanner ==
                          "nessus" else self.RAPID7_STRINGS_TO_FILTER)

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
        
        # create summary page
        summary_page = self.create_summary_sheet(issues)
        
        found_vulnerabilities = [
            {"dataframe": issue[1], "sheetname": f"{issue[0]}"}
            for issue in issues.items()
        ]
        
        # append the first sheet to the list of found vulnerabilities
        found_vulnerabilities.insert(0, {"dataframe": summary_page, "sheetname": "Summary"})
      
        self.save_vulns_to_files(
            unfiltered_data=unfiltered,
            found_vulnerabilities=found_vulnerabilities,
            output_file=output_file,
        )

    def create_summary_sheet(self, issues:dict):
        """Create a summary page for the vulnerabilities
        :param: issues ==> Dictionary containing key, value pair of dataframe
        :return: Dataframe
        """
        summary_rows =[]
        for _, dataframe in issues.items():
            if dataframe.empty:
                continue
            
            # Group unique vulnerabilities 
            if self.scanner == "nessus":
                grouped = dataframe.groupby("Name")
                title_field = 'Name'
                desc_field = 'Description'
                impact_field = 'Risk'
                solution_field = 'Solution'
            else:
                grouped = dataframe.groupby("Vulnerability Title")
                title_field = 'Vulnerability Title'
                desc_field = 'Vulnerability Description'
                impact_field = 'Vulnerability Severity Level'
                solution_field = 'Vulnerability Solution'
                
            for name, group in grouped:
                affected_hosts = ', '.join(group['Host'].unique() if self.scanner == "nessus" 
                                     else group['Asset IP Address'].unique())
                summary_rows.append({
                'S.No': len(summary_rows) + 1,
                'Observation': name,
                'Description': '', # Empty column for manual input
                'Impact': '', # Empty 
                'Risk Rating': '', # Empty 
                'Recommendation':'', # Empty 
                'Affected Hosts': affected_hosts,
                'Management Response': ''  # Empty column for manual input
            })
            
        # Create a summary dataframe
        summary_df = self.create_pd_dataframe(summary_rows, self.SUMMARY_SHEET_HEADERS)
        return summary_df
                

            
            

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
