# trunk-ignore-all(isort)
from handlers import FileHandler


class VulnerabilityAnalysis:
    def __init__(self, filemanager: FileHandler) -> None:
        self.filemanager = filemanager
        self.data = []
        self.credentialed_hosts = []
        self.headers = [
            "CVE",
            "Risk",
            "Host",
            "Protocol",
            "Port",
            "Name",
            "Synopsis",
            "Description",
            "Solution",
            "See Also",
        ]
        self.selected_columns = []

    def percentage_null(self, dataframe):
        # determine percentage accuracy of the data
        for i in dataframe.columns:
            null_rate = dataframe[i].isna().sum() / len(dataframe) * 100
            if null_rate > 0:
                print(f"{i} null rate: {null_rate:.2f}%")

    def analyze_csv(self, csv_data):
        # read csv data and return analyzed file
        self.data = self.filemanager.read_excel_file(csv_data)

        # lists of hosts that passed credential check

        credentialed_hosts = self.data[
            (self.data["Plugin Output"].notna())
            & (self.data["Plugin Output"].str.contains("Credentialed checks : yes"))
        ]["Host"]
        self.credentialed_hosts = list(credentialed_hosts.values)

        selected_columns = self.data[self.data["Host"].isin(self.credentialed_hosts)][
            self.headers
        ]

        # Return only [ Critical | High | Medium ] Risks and notnull values
        formated_vulns = selected_columns[
            (self.data["Risk"].notna()) & (selected_columns["Risk"] != "Low")
        ].reset_index(drop=True)

        return formated_vulns

    def regex_word(self, search_term, **kwargs):
        if "is_extra" in kwargs:
            return rf'\b{search_term}\b(?!.*\b{kwargs["second_term"]}\b)'
        return rf"\b{search_term}\b"

    def sort_vulnerabilities(self, vulnerabilities, output_file):
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
            ],
            output_file,
        )
