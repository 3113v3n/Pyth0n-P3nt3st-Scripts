from ..colors import Bcolors
import re


class VAConfigs:
    color = Bcolors

    def __init__(self):
        self._compiled_patterns = {
            "ssl": self._compile_regex(self.SSL_FILTER_STRINGS),
            "software": self._compile_regex(self.UPGRADE_FILTER_STRINGS),
            "reboot": self._compile_regex(self.REBOOT_FILTER_STRINGS),
            "patch": self._compile_regex(self.PATCH_FILTER_STRINGS),
            "rdp": self._compile_regex(self.RDP_FILTER_STRINGS),
            "web": self._compile_regex(self.WEB_FILTER_STRINGS),
            "ignore_": {"common": self._compile_regex(self.UNIVERSAL_IGNORE_FILTER),
                        "web": self._compile_regex(self.WEB_IGNORE_FILTER)},
            "compliance": self._compile_regex(self.COMPLIANCE_STRINGS),
            "rating": self._compile_regex(self.RISK_RATING_STRINGS),
            "rce": self._compile_regex(self.RCE_STRING),
            "patch_or_upgrade": self._compile_regex(self.PATCH_OR_UPGRADE),
            "ssh": self._compile_regex(self.SSH_STRINGS),
            "info": self._compile_regex(self.INFO_DISCLOSURE_STRINGS)
        }

    def _compile_regex(self, string_pattern):
        return re.compile(string_pattern)

    NESSUS_HEADERS = [
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
        "Plugin Output",
    ]
    SUMMARY_SHEET_HEADERS = [
        "S.No",
        "Observation",
        "Description",
        "Impact",
        "Risk Rating",
        "Recommendation",
        "Affected Hosts",
        "Management Response",
    ]

    RAPID7_HEADERS = [
        "Vulnerability Title",
        "Asset Names",
        "Custom Tag",
        "Asset IP Address",
        "Asset Alternate IPv4 Addresses",
        "Asset OS Name",
        "Asset OS Family",
        "Service Name",
        "Asset OS Version",
        "Service Port",
        "Vulnerability Description",
        "Vulnerability CVE IDs",
        "Vulnerability CVSS Score",
        "Vulnerability Solution",
        "Exploit Count",
        "Exploit URLs",
        "Malware Kit Count",
        "Exploit Minimum Skill",
        "Asset Risk Score",
        "Asset MAC Addresses",
        "Vulnerability Severity Level",
        "Vulnerability CVE URLs",
        "Vulnerability Risk Score",
        "Vulnerability PCI Compliance Status",
        "Vulnerable Since",
    ]

    column_mismatch_error = (
        f"{Bcolors.FAIL}{Bcolors.BOLD}[!]Column mismatch between files. "
        f" Ensure all files have the same number of columns {Bcolors.ENDC}"
    )

    NESSUS_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software_condition",
        "Kaspersky": "kaspersky_condition",
        "Insecure Service": "insecure_condition",
        "Winverify": "winverify_condition",
        "Unquoted Service Path": "unquoted_condition",
        "SMB Issues": "smb_condition",
        "Windows Speculative": "speculative_condition",
        "Active Directory": "AD_condition",
        "Windows Defender": "defender_condition",
        "RDP Misconfig": "rdp_condition",
        "SSH Misconfig": "ssh_condition",
        "Telnet": "telnet_condition",
        "Remote Code Execution": "rce_condition",
        "Information Disclosure": "information_condition",
        "Web Application Issues": "web_condition",
        "Windows Update Reboot": "reboot_condition",
        "Compliance": "compliance_condition",
    }
    RAPID7_VULN_CATEGORIES = {
        "SSL Misconfigurations": "ssl_condition",
        "Missing Patches": "missing_patch_condition",
        "Unsupported Software": "unsupported_software_condition",
        "SSH Misconfig": "ssh_condition",
        "Database Misconfigurations": "database_condition",
        "Web Application Issues": "web_condition",
        "Compliance": "compliance_condition",
    }
    SCAN_FILE_FORMAT = ("csv", "xlsx", "both")
    SSL_FILTER_STRINGS = "SSL|TLS|POODLE|Diffie-Hellman"
    PATCH_FILTER_STRINGS = (
        "[Pp]atch(?:es)|[Pp]atch|[Uu]pdat(?:e|es|ing)|[Ss]ecurity (?:[Uu]pdat(?:e|es)|[Pp]atch)|Microsoft has released|"
        "JDK [Uu]pdate|JRE [Uu]pdate|Java [Uu]pdate|[Uu]pdate \\d+|Apply|[Ii]nstall patch"
    )
    UPGRADE_FILTER_STRINGS = (
        "no longer supported|[Uu]nsupported|Obsolete Version|end of life|"
        "end-of-life|[Uu]pgrad(?:e|ing)|discontinu(?:e|ed)|is prior to \\d+|remove any affected versions|"
        "[Uu]pgrade to|[Uu]ninstall"

    )
    REBOOT_FILTER_STRINGS = "[rR]eboot"
    RDP_FILTER_STRINGS = "Terminal Services|[Rr]emote [Dd]esktop [Pp]rotocol|NLA"
    WEB_FILTER_STRINGS = "Web|web server|HTTP|HSTS|HTTPS|IIS|ASP.NET|[Hh]eader"
    UNIVERSAL_IGNORE_FILTER = "[Uu]pgrade|[Uu]pdate|[Pp]atch"
    WEB_IGNORE_FILTER = "TLS|SSL"
    RISK_RATING_STRINGS = "Critical|High|Medium"
    COMPLIANCE_STRINGS = "FAILED|WARNING|Fail"
    RCE_STRING = "[Rr]emote [Cc]ode [Ee]xecution"
    PATCH_OR_UPGRADE = "[Uu]pdate|[Uu]pgrade"
    SSH_STRINGS = "SSH|SSH [Ss]erver"
    INFO_DISCLOSURE_STRINGS = "[Ii]nformation [Dd]isclosure"
    # Scanner-specific column mappings
    COLUMNS = {
        "nessus": {
            "title": "Name",
            "solution": "Solution",
            "description": "Description",
            "synopsis": "Synopsis",
            "risk": "Risk",
        },
        "rapid": {
            "title": "Vulnerability Title",
            "solution": "Vulnerability Solution",
            "service": "Service Name",
            "pci_status": "Vulnerability PCI Compliance Status",
        },
    }
    HEADLINE = f"\n{color.HEADER}[*]INFO[*]{color.ENDC}\n"
    VULNERABILITY_HELPER_STRING = f"""{HEADLINE}
    Runs Vulnerability analysis on 1 or multiple scans generated by Nessus or Rapid7

    Ensure the scan results have {color.BOLD}all column headers of equal number{color.ENDC} to avoid
    errors.
    For Nessus, the scan filters out only {color.UNDERLINE}{color.BOLD}Credentialed{color.ENDC} scans
    
    {color.OKCYAN}{color.UNDERLINE}required arguments{color.ENDC}:

            {color.OKGREEN}scan_folder{color.ENDC}      File Path to your scan results
            {color.OKGREEN}scanner{color.ENDC}          The scanner used [ {color.WARNING}Nessus | Rapid7{color.ENDC} ]
            {color.OKGREEN}file_type{color.ENDC}        The output filetype [ {color.WARNING}CSV | XLSX | Both{color.ENDC} ]
            {color.OKGREEN}filename{color.ENDC}         The name of your output file

    {color.OKCYAN}{color.UNDERLINE}return {color.ENDC}:
            {color.OKGREEN}filtered_list{color.ENDC}    Output file with the filtered vulnerabilities
            {color.OKGREEN}unfiltered_list{color.ENDC}  File containing list of all vulnerabilities that
                              were not analyzed, for manual input
{HEADLINE}"""
