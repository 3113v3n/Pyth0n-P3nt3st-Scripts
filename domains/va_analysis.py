# trunk-ignore-all(isort)
from handlers import FileHandler
from utils.shared import Config

# from pprint import pprint


class VulnerabilityAnalysis:
    def __init__(self, filemanager: FileHandler, config: Config) -> None:
        self.filemanager = filemanager
        self.data = []
        self.credentialed_hosts = []
        self.headers = config.va_headers
        self.selected_columns = []
        self.config = config

    def percentage_null(self, dataframe):
        # determine percentage accuracy of the data
        for i in dataframe.columns:
            null_rate = dataframe[i].isna().sum() / len(dataframe) * 100
            if null_rate > 0:
                print(f"{i} null rate: {null_rate:.2f}%")

    def format_input_file(self):
        # lists of hosts that passed credential check

        credentialed_hosts = self.data[
            (self.data["Plugin Output"].notna())
            & (self.data["Plugin Output"].str.contains("Credentialed checks : yes"))
        ]["Host"].tolist()
        self.credentialed_hosts = credentialed_hosts

        selected_columns = self.data[self.data["Host"].isin(self.credentialed_hosts)][
            self.headers[:-1]
        ]

        # Return only [ Critical | High | Medium ] Risks and notnull values
        formated_vulns = selected_columns[
            (selected_columns["Risk"].notna()) & (selected_columns["Risk"] != "Low")
        ].reset_index(drop=True)
        print(f"Credentialed Hosts: \n{self.credentialed_hosts}")

        return formated_vulns

    def analyze_csv(self, csv_data):
        """
        Checks if the provided argument is a string containing a csv file or a tuple containing
        a list of csv files and the index of the user selected file we then return a list
        """

        if isinstance(csv_data, tuple):
            file_list = csv_data[0]
            start_index = csv_data[1]
            start_file = file_list[start_index]["full_path"]
            try:
                # Read the first file as baseline
                original_file = self.filemanager.read_csv(start_file)
                print(
                    f"original file {start_file} has {len(original_file.columns)} columns "
                )
                # Check if baseline file is empty
                if original_file.empty:
                    raise ValueError(
                        f"Baseline file {file_list[start_index]['filename']} is empty"
                    )

                # Check missing columns in basefile
                missing_columns = list(
                    set(self.config.va_headers) - set(original_file.columns)
                )
                # Check if files have missing columns
                if missing_columns:
                    raise KeyError(
                        f"The following columns are missing from the {start_file} \n{missing_columns}"
                    )

                all_vulns = original_file

                # Iterate through the list of files and append data from each file
                for file in file_list:
                    if file["full_path"] != start_file:
                        # Read CSV file without headers
                        new_data = self.filemanager.read_csv(
                            file["full_path"], header=None
                        )

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
                        missing_columns = list(
                            set(self.config.va_headers) - set(new_data.columns)
                        )
                        # Check if other files have missing columns
                        if missing_columns:
                            raise KeyError(
                                f"The following columns are missing from the {file['full_path']} \n{missing_columns}"
                            )
                        # Append new data to the original data
                        all_vulns = self.filemanager.concat_dataframes(
                            all_vulns, new_data
                        )

                self.data = all_vulns
            except (ValueError, KeyError) as error:
                print(error)

        else:
            # read csv data and return analyzed file
            self.data = self.filemanager.read_csv(csv_data)
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
        ]
        # 1. SSL issues
        ssl_issues = vulnerabilities[conditions["ssl_condition"]]

        # 2. Missing Patches and Security Updates
        missing_patches = vulnerabilities[conditions["missing_patch_condition"]]
        # 3. Unsupported Software
        """ Capture only vulnerabilities that require Upgrade """
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

        found_vulns = [
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
        ]
        unfiltered_vulns = [{"dataframe": unfiltered, "sheetname": "Unfiltered"}]
        if not unfiltered.empty:
            self.filemanager.write_to_multiple_sheets(
                unfiltered_vulns,
                "Unfiltered Vulnerabilities",
            )

        self.filemanager.write_to_multiple_sheets(
            found_vulns,
            output_file,
        )


# TODO:
# 1 return unfiltered Dataframe for manual analysis
