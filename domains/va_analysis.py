# trunk-ignore-all(isort)
from pprint import pprint
from utils.shared import Config
from handlers import FileHandler
from handlers.file_handler import read_csv, concat_dataframes


def percentage_null_fields(dataframe):
    # determine percentage accuracy of the data by showing null fields
    for i in dataframe.columns:
        null_rate = dataframe[i].isna().sum() / len(dataframe) * 100
        if null_rate > 0:
            print(f"{i} null rate: {null_rate:.2f}%")


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


class VulnerabilityAnalysis:
    """Class that handles Vulnerability analysis tasks"""

    def __init__(self, filemanager: FileHandler, config: Config) -> None:
        # File manager class that is responsible for file operations
        self.filemanager = filemanager
        self.data = []
        # list of hosts that passed credential check
        self.credentialed_hosts = []
        # CSV headers used for analysis
        self.headers = config.va_headers
        # columns to showcase on our final excel
        self.selected_columns = []
        # contains constants to be used across the program
        self.config = config

    def format_input_file(self) -> list:
        # lists of hosts that passed credential check
        # filter hosts with credential check successful

        credentialed_hosts = self.data[
            (csv_filter_operations(self.data, "Plugin Output", "notnull"))
            & (
                csv_filter_operations(
                    self.data,
                    "Plugin Output",
                    "contains",
                    contains_key="Credentialed checks : yes",
                )
            )
        ]["Host"].tolist()
        self.credentialed_hosts = credentialed_hosts

        selected_columns = self.data[
            csv_filter_operations(
                self.data, "Host", "in", in_key=self.credentialed_hosts
            )
        ][
            self.headers[:-1]  # ignore the last item in our headers list
        ]

        # Return only [ Critical | High | Medium ] Risks and notnull values
        formated_vulnerabilities = selected_columns[
            (csv_filter_operations(selected_columns, "Risk", "notnull"))
            & (selected_columns["Risk"] != "Low")
        ].reset_index(drop=True)
        print(f"\nCredentialed Hosts: \n{self.credentialed_hosts}")

        return formated_vulnerabilities

    def get_missing_columns(self, dataframe, filename):
        # compare the headers from our defined headers and provided dataframe
        missing_columns = list(set(self.config.va_headers) - set(dataframe.columns))
        if missing_columns:
            raise KeyError(
                f"The following columns are missing from the {filename} \n{missing_columns}"
            )

    def analyze_csv(self, csv_data):
        """
        Checks if the provided argument is a string containing a csv file or a tuple containing
        a list of csv files and the index of the user selected file we then return a list

        ( [list_of_csv_files], index_of_selected_file )
        """

        # if isinstance(csv_data, tuple):
        file_list = csv_data[0]
        starting_index = csv_data[1]
        starting_file = file_list[starting_index]["full_path"]
        try:
            # Read the first file as baseline
            filename = file_list[starting_index]["filename"]
            original_file = read_csv(starting_file)

            # Check if baseline file is empty
            if original_file.empty:
                raise ValueError(f"Baseline file {filename} is empty")

            # Check missing columns in base file
            self.get_missing_columns(original_file, filename)
            all_vulnerabilities = original_file

            # Iterate through the list of files and append data from each file
            for file in file_list:
                if file["full_path"] != starting_file:
                    # Read CSV file without headers
                    new_data = read_csv(file["full_path"], header=None)

                    # Check if new data is empty
                    if new_data.empty:
                        print(f"Skipping empty file : {file['filename']}")
                        continue

                    # Ensure columns match
                    if original_file.shape[1] != new_data.shape[1]:
                        print(
                            f"New file {file['filename']} has {len(new_data.columns)} columns "
                        )
                        raise ValueError(self.config.column_mismatch_error)

                    # Check if other files have missing columns
                    self.get_missing_columns(new_data, file["filename"])
                    # Append new data to the original data
                    all_vulnerabilities = concat_dataframes(
                        all_vulnerabilities, new_data
                    )

            self.data = all_vulnerabilities
        except (ValueError, KeyError) as error:
            print(error)

        return self.format_input_file()

    def regex_word(self, search_term, **kwargs):
        if "is_extra" in kwargs:
            return rf'\b{search_term}\b(?!.*\b{kwargs["second_term"]}\b)'
        return rf"\b{search_term}\b"

    def sort_vulnerabilities(self, vulnerabilities, output_file):
        conditions = self.config.filter_conditions(
            vulnerabilities, regex_word=self.regex_word
        )
        # Show remaining data after filtering
        unfiltered = vulnerabilities[
            ~conditions["ssl_condition"]
            & ~conditions["missing_patch_condition"]
            & ~conditions["unsupported_software"]
            & ~conditions["kaspersky_condition"]
            & ~conditions["insecure_condition"]
            & ~conditions["winverify_condition"]
            & ~conditions["unquoted_condition"]
            & ~conditions["smb_condition"]
            & ~conditions["speculative_condition"]
            & ~conditions["AD_condition"]
            & ~conditions["defender_condition"]
            & ~conditions["rdp_condition"]
            & ~conditions["compliance_condition"]
            & ~conditions["ssh_condition"]
            & ~conditions["telnet_condition"]
            & ~conditions["information_condition"]
            & ~conditions["web_condition"]
            & ~conditions["rce_condition"]
        ]
        # 1. SSL issues
        ssl_issues = vulnerabilities[conditions["ssl_condition"]]

        # 2. Missing Patches and Security Updates
        missing_patches = vulnerabilities[conditions["missing_patch_condition"]]
        # 3. Unsupported Software
        unsupported = vulnerabilities[conditions["unsupported_software"]]
        # 4. Kaspersky
        kaspersky = vulnerabilities[conditions["kaspersky_condition"]]

        # 5. Windows Service Permission
        insecure_service = vulnerabilities[conditions["insecure_condition"]]
        # 6. WinVerify
        winverify = vulnerabilities[conditions["winverify_condition"]]
        # 7. Unquoted Service Path
        unquoted = vulnerabilities[conditions["unquoted_condition"]]
        # 8. SMB misconfiguration
        smb_issues = vulnerabilities[conditions["smb_condition"]]
        # 9. Windows Speculative
        speculative = vulnerabilities[conditions["speculative_condition"]]

        # 10. AD Misconfigurations
        active_directory = vulnerabilities[conditions["AD_condition"]]

        # 11. Microsoft
        defender = vulnerabilities[conditions["defender_condition"]]

        # 12. RDP misconfigs
        rdp_misconfig = vulnerabilities[conditions["rdp_condition"]]

        # 13. Compliance Checks
        compliance = vulnerabilities[conditions["compliance_condition"]]
        # 14. SSH misconfig
        ssh_misconfig = vulnerabilities[conditions["ssh_condition"]]
        # 15. Telnet
        telnet = vulnerabilities[conditions["telnet_condition"]]
        # 16. Info Disclosure
        information_disclosure = vulnerabilities[conditions["information_condition"]]
        # 17, Web Issues
        web_issues = vulnerabilities[conditions["web_condition"]]
        # 18. Remote Code execution
        rce = vulnerabilities[
            conditions["rce_condition"]
            & ~conditions["missing_patch_condition"]
            & ~conditions["unsupported_software"]
        ]

        found_vulnerabilities = [
            {"dataframe": winverify, "sheetname": "winverify"},
            {"dataframe": unquoted, "sheetname": "Unquoted Service"},
            {"dataframe": smb_issues, "sheetname": "SMB Issues"},
            {"dataframe": ssl_issues, "sheetname": "SSL issues"},
            {"dataframe": missing_patches, "sheetname": "Missing Security Updates"},
            {"dataframe": unsupported, "sheetname": "Unsupported Software"},
            {"dataframe": kaspersky, "sheetname": "Kaspersky Misconfigs"},
            {"dataframe": ssh_misconfig, "sheetname": "SSH Misconfig"},
            {"dataframe": rdp_misconfig, "sheetname": "RDP Misconfig"},
            {"dataframe": defender, "sheetname": "Windows Defender"},
            {"dataframe": rce, "sheetname": "RCE"},
            {"dataframe": active_directory, "sheetname": "AD misconfig"},
            {
                "dataframe": insecure_service,
                "sheetname": "Insecure Windows Services",
            },
            {"dataframe": speculative, "sheetname": "Windows Speculative"},
            {"dataframe": compliance, "sheetname": "Compliance checks"},
            {"dataframe": telnet, "sheetname": "Unencrypted Telnet"},
            {
                "dataframe": information_disclosure,
                "sheetname": "Information Disclosure",
            },
            {"dataframe": web_issues, "sheetname": "Web Issues"},
        ]
        unfiltered_vulnerabilities = [
            {"dataframe": unfiltered, "sheetname": "Unfiltered"}
        ]
        
        if not unfiltered.empty:
            self.filemanager.write_to_multiple_sheets(
                unfiltered_vulnerabilities,
                "Unfiltered Vulnerabilities",
            )

        self.filemanager.write_to_multiple_sheets(
            found_vulnerabilities,
            output_file,
        )
