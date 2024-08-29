# trunk-ignore-all(isort)
from handlers import FileHandler
from utils.shared import Config
#from pprint import pprint


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
            self.headers
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

            # Read the first file as baseline
            original_file = self.filemanager.read_csv(start_file)

            # Check if baseline file is empty
            if original_file.empty:
                raise ValueError(f"Baseline file {original_file} is empty")

            all_vulns = original_file

            # Iterate through the list of files and append data from each file
            for file in file_list:
                if file["full_path"] != start_file:
                    # Read CSV file without headers
                    new_data = self.filemanager.read_csv(file["full_path"], header=None)

                    # Check if new data is empty
                    if new_data.empty:
                        print(f"Skipping empty file : {file['full_path']}")
                        continue

                    # Ensure columns match
                    if original_file.shape[1] != new_data.shape[1]:
                        raise ValueError(self.config.column_mismatch_error)

                    # Append new data to the original data
                    all_vulns = self.filemanager.concat_dataframes(all_vulns, new_data)

            self.data = all_vulns

        else:
            # read csv data and return analyzed file
            self.data = self.filemanager.read_csv(csv_data)
        return self.format_input_file()

    def regex_word(self, search_term, **kwargs):
        if "is_extra" in kwargs:
            return rf'\b{search_term}\b(?!.*\b{kwargs["second_term"]}\b)'
        return rf"\b{search_term}\b"

    def sort_vulnerabilities(self, vulnerabilities, output_file):
        # pprint(vulnerabilities)
        # 1. SSL issues
        ssl_issues = vulnerabilities[
            vulnerabilities["Name"].str.contains(self.regex_word("SSL"), regex=True)
        ]

        # 2. Missing Patches and Security Updates
        missing_patches = vulnerabilities[
            vulnerabilities["Solution"].str.contains(
                self.regex_word("Update"), regex=True
            )
            | (vulnerabilities["Solution"].str.contains(self.regex_word("patches")))
        ]
        # 3. Unsupported Software
        """ Capture only vulnerabilities that require Upgrade """
        unsupported = vulnerabilities[
            (
                vulnerabilities["Solution"].str.contains(
                    self.regex_word("Upgrade", is_extra=True, second_term="Update"),
                    regex=True,
                )
            )
        ]
        # 4. Kaspersky
        kaspersky = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("Kaspersky"), regex=True
            )
        ]

        # 5. Windows Service Permission
        insecure_service = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("Insecure Windows Service"), regex=True
            )
        ]
        # 6. WinVerify
        winverify = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("WinVerifyTrust"), regex=True
            )
        ]
        # 7. Unquoted Service Path
        unquoted = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("Unquoted Service Path"), regex=True
            )
        ]
        # 8. SMB misconfiguration
        smb_issues = vulnerabilities[
            vulnerabilities["Name"].str.contains(self.regex_word("SMB"), regex=True)
        ]
        # 9. Windows Speculative
        speculative = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("Windows Speculative"), regex=True
            )
        ]

        # 10. AD Misconfigurations
        active_directory = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("AD Starter"), regex=True
            )
        ]

        # 11. Microsoft
        defender = vulnerabilities[
            vulnerabilities["Synopsis"].str.contains(
                self.regex_word("antimalware"), regex=True
            )
        ]

        # 12. RDP misconfigs
        rdp_misconfig = vulnerabilities[
            (
                vulnerabilities["Name"].str.contains(
                    self.regex_word("Terminal Services"), regex=True
                )
            )
            | (
                vulnerabilities["Name"].str.contains(
                    self.regex_word("Remote Desktop Protocol"), regex=True
                )
            )
        ]

        # 13. Compliance Checks
        compliance = vulnerabilities[
            vulnerabilities["Synopsis"].str.contains(
                self.regex_word("Compliance checks"), regex=True
            )
        ]
        # 14. SSH misconfig
        ssh_misconfig = vulnerabilities[
            vulnerabilities["Synopsis"].str.contains(
                self.regex_word("SSH server"), regex=True
            )
        ]
        # 15. Telnet
        telnet = vulnerabilities[
            vulnerabilities["Name"].str.contains(
                self.regex_word("Telnet Server"), regex=True
            )
        ]

        self.filemanager.write_to_multiple_sheets(
            [
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
            ],
            output_file,
        )
